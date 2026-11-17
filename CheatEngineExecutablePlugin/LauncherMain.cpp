#include "../Ksword5.1/Ksword5.1/ArkDriverClient/ArkDriverClient.h"
#include "../DebuggerBackend/KswordRandomizedPayload.h"
#include "LogSurface.h"

#include <Windows.h>

#include <algorithm>
#include <atomic>
#include <memory>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cwchar>
#include <fstream>
#include <string>
#include <thread>
#include <vector>

namespace
{
    constexpr wchar_t kPluginTitle[] = L"KSword Cheat Engine";
    constexpr wchar_t kTabWindowClass[] = L"KSwordCheatEngineLogSurface";
    constexpr char kProtocol[] = "ksword-plugin/1";
    constexpr char kPluginId[] = "cheat-engine";
    constexpr UINT kInitializeTabMessage = WM_APP + 1U;
    constexpr UINT_PTR kLifecycleTimerId = 1U;
    const UINT kAsyncResizeMessage = ::RegisterWindowMessageW(L"KSword.PluginTab.ResizeParentClient.v1");

    struct ParsedArguments
    {
        std::wstring command;
        DWORD targetProcessId = 0U;
        DWORD targetThreadId = 0U;
        std::wstring noAttachMode; // L"", L"hvm" or L"kernel"
        HWND parentWindow = nullptr;
        DWORD hostProcessId = 0U;
        bool valid = false;
    };

    enum class BridgeStatus
    {
        ready,
        failed,
        timeout,
        launchFailed
    };

    HWND gTabWindow = nullptr;
    HWND gLogView = nullptr;
    HWND gHostParentWindow = nullptr;
    HANDLE gCheatEngineProcess = nullptr;
    DWORD gHostProcessId = 0U;
    int gTabExitCode = 0;
    std::wstring gLogPath;
    std::streamoff gLogOffset = 0;
    std::string gPendingLogLine;
    std::string gLaunchFailureMessage;
    // 随机命名克隆的 CE payload 目录；CE 退出后在 WM_TIMER 分支内清理。
    std::wstring gClonedCeDirectory;

    struct TabLaunchTask {
        std::atomic_bool canceled{false};
        std::thread worker;
        DWORD processId = 0;
        HANDLE process = nullptr;
        std::wstring logPath;
        BridgeStatus status = BridgeStatus::launchFailed;
        bool driverReady = false;
        std::string failure;
        ~TabLaunchTask() { if (process) ::CloseHandle(process); }
    };
    std::shared_ptr<TabLaunchTask> gTabLaunchTask; // Native owner thread only.

    std::string escapeJson(const std::string& value);

    std::string toUtf8(const std::wstring& value)
    {
        if (value.empty())
        {
            return {};
        }
        const int length = ::WideCharToMultiByte(
            CP_UTF8, 0U, value.data(), static_cast<int>(value.size()),
            nullptr, 0, nullptr, nullptr);
        if (length <= 0)
        {
            return {};
        }
        std::string converted(static_cast<std::size_t>(length), '\0');
        (void)::WideCharToMultiByte(
            CP_UTF8, 0U, value.data(), static_cast<int>(value.size()),
            converted.data(), length, nullptr, nullptr);
        return converted;
    }

    std::string windowsFailure(
        const char* const operation,
        const std::wstring& path,
        const DWORD error)
    {
        wchar_t systemMessage[512]{};
        (void)::FormatMessageW(
            FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            nullptr, error, 0U, systemMessage, _countof(systemMessage), nullptr);
        std::wstring detail(systemMessage);
        while (!detail.empty() && (detail.back() == L'\r' || detail.back() == L'\n'))
        {
            detail.pop_back();
        }
        return std::string(operation) + ": " + toUtf8(path) +
            " (Win32 error " + std::to_string(error) +
            (detail.empty() ? ")" : ": " + toUtf8(detail) + ")");
    }

    bool verifyPayloadFile(const std::wstring& path, const char* const description)
    {
        WIN32_FILE_ATTRIBUTE_DATA attributes{};
        if (::GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &attributes) == FALSE)
        {
            const DWORD error = ::GetLastError();
            gLaunchFailureMessage = windowsFailure(description, path, error);
            return false;
        }
        if ((attributes.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0U ||
            (attributes.nFileSizeHigh == 0U && attributes.nFileSizeLow == 0U))
        {
            gLaunchFailureMessage = windowsFailure(description, path, ERROR_BAD_EXE_FORMAT);
            return false;
        }
        return true;
    }

    void emitJsonLine(const std::string& eventName, const std::string& fields)
    {
        std::string line =
            "{\"protocol\":\"" + std::string(kProtocol) +
            "\",\"plugin_id\":\"" + std::string(kPluginId) +
            "\",\"event\":\"" + eventName + "\"";
        if (!fields.empty())
        {
            line += ",";
            line += fields;
        }
        line += "}\n";

        const HANDLE stdoutHandle = ::GetStdHandle(STD_OUTPUT_HANDLE);
        if (stdoutHandle == nullptr || stdoutHandle == INVALID_HANDLE_VALUE)
        {
            return;
        }
        DWORD written = 0U;
        (void)::WriteFile(
            stdoutHandle,
            line.data(),
            static_cast<DWORD>(line.size()),
            &written,
            nullptr);
    }

    void emitError(const char* const code, const char* const message)
    {
        emitJsonLine(
            "error",
            "\"code\":\"" + escapeJson(code) +
            "\",\"message\":\"" + escapeJson(message) + "\"");
    }

    bool parseUnsignedProcessId(const std::wstring& text, DWORD* const valueOut)
    {
        if (valueOut == nullptr || text.empty())
        {
            return false;
        }
        wchar_t* end = nullptr;
        errno = 0;
        const unsigned long long value = std::wcstoull(text.c_str(), &end, 10);
        if (errno != 0 || end == text.c_str() || *end != L'\0' ||
            value == 0ULL || value > static_cast<unsigned long long>(MAXDWORD))
        {
            return false;
        }
        *valueOut = static_cast<DWORD>(value);
        return true;
    }

    bool parseWindowHandle(const std::wstring& text, HWND* const valueOut)
    {
        if (valueOut == nullptr || text.empty())
        {
            return false;
        }
        wchar_t* end = nullptr;
        errno = 0;
        const unsigned long long value = std::wcstoull(text.c_str(), &end, 10);
        if (errno != 0 || end == text.c_str() || *end != L'\0' || value == 0ULL)
        {
            return false;
        }
        const auto numericHandle = static_cast<std::uintptr_t>(value);
        if (static_cast<unsigned long long>(numericHandle) != value)
        {
            return false;
        }
        *valueOut = reinterpret_cast<HWND>(numericHandle);
        return true;
    }

    ParsedArguments parseArguments(const int argc, wchar_t* const argv[])
    {
        ParsedArguments parsed;
        if (argc < 3 || std::wstring(argv[1]) != L"--ksword-plugin")
        {
            return parsed;
        }
        parsed.command = argv[2];
        if (parsed.command == L"info" || parsed.command == L"check")
        {
            parsed.valid = true;
            return parsed;
        }
        if (parsed.command != L"launch" && parsed.command != L"tab")
        {
            return parsed;
        }

        for (int index = 3; index + 1 < argc; ++index)
        {
            const std::wstring argument = argv[index];
            if (argument == L"--pid")
            {
                if (!parseUnsignedProcessId(
                        argv[index + 1],
                        &parsed.targetProcessId))
                {
                    return parsed;
                }
                ++index;
            }
            else if (argument == L"--parent-hwnd")
            {
                if (!parseWindowHandle(argv[index + 1], &parsed.parentWindow))
                {
                    return parsed;
                }
                ++index;
            }
            else if (argument == L"--host-pid")
            {
                if (!parseUnsignedProcessId(
                        argv[index + 1],
                        &parsed.hostProcessId))
                {
                    return parsed;
                }
                ++index;
            }
            else if (argument == L"--tid")
            {
                if (!parseUnsignedProcessId(
                        argv[index + 1],
                        &parsed.targetThreadId))
                {
                    return parsed;
                }
                ++index;
            }
            else if (argument == L"--noattach-mode")
            {
                const std::wstring mode = argv[index + 1];
                if (mode != L"hvm" && mode != L"kernel")
                {
                    return parsed;
                }
                parsed.noAttachMode = mode;
                ++index;
            }
        }
        // No-attach selection is optional; both parts must match when supplied.
        if ((parsed.targetThreadId != 0U) != !parsed.noAttachMode.empty())
        {
            return parsed;
        }
        if (parsed.command == L"launch")
        {
            parsed.valid = parsed.targetProcessId != 0U;
            return parsed;
        }

        DWORD parentOwnerProcessId = 0U;
        if (parsed.parentWindow == nullptr ||
            parsed.hostProcessId == 0U ||
            !::IsWindow(parsed.parentWindow) ||
            ::GetWindowThreadProcessId(
                parsed.parentWindow,
                &parentOwnerProcessId) == 0U ||
            parentOwnerProcessId != parsed.hostProcessId)
        {
            return parsed;
        }
        parsed.valid = true;
        return parsed;
    }

    std::wstring currentExecutablePath()
    {
        std::vector<wchar_t> buffer(32768U, L'\0');
        const DWORD length = ::GetModuleFileNameW(
            nullptr,
            buffer.data(),
            static_cast<DWORD>(buffer.size()));
        if (length == 0U || length >= static_cast<DWORD>(buffer.size()))
        {
            return {};
        }
        return std::wstring(buffer.data(), length);
    }

    std::wstring parentDirectory(const std::wstring& path)
    {
        const std::wstring::size_type separator = path.find_last_of(L"\\/");
        if (separator == std::wstring::npos)
        {
            return {};
        }
        return path.substr(0U, separator);
    }

    std::wstring joinPath(
        const std::wstring& directory,
        const std::wstring& relativePath)
    {
        if (directory.empty())
        {
            return relativePath;
        }
        return directory + L"\\" + relativePath;
    }

    bool verifyPayloadFiles(const std::wstring& pluginDirectory)
    {
        gLaunchFailureMessage.clear();
        return verifyPayloadFile(
                joinPath(pluginDirectory, L"payload\\Cheat Engine\\cheatengine-x86_64.exe"),
                "Cheat Engine executable is missing or invalid") &&
            verifyPayloadFile(
                joinPath(pluginDirectory, L"bridge\\x64\\KswordCheatEnginePlugin.dll"),
                "KSword CE bridge DLL is missing or invalid") &&
            verifyPayloadFile(joinPath(pluginDirectory, L"payload\\Cheat Engine\\autorun\\10_ksword_bridge.lua"),
                "KSword CE startup script is missing or invalid") &&
            verifyPayloadFile(joinPath(pluginDirectory, L"payload\\Cheat Engine\\autorun\\ksword_hvm.lua"),
                "KSword debugger API script is missing or invalid");
    }

    bool isDriverReady()
    {
        const ksword::ark::DriverClient driverClient;
        auto driverHandle = driverClient.open();
        return driverHandle.isValid();
    }

    bool confirmR0OrWarn(bool* const driverReadyOut)
    {
        if (driverReadyOut == nullptr)
        {
            return false;
        }
        *driverReadyOut = isDriverReady();
        if (*driverReadyOut)
        {
            return true;
        }

        const int retryResult = ::MessageBoxW(
            nullptr,
            L"KSword R0 驱动当前不可用。\n\n"
            L"请回到 KSword 启用 R0 模式并加载驱动，然后点击“重试”。",
            kPluginTitle,
            MB_RETRYCANCEL | MB_ICONWARNING | MB_SETFOREGROUND);
        if (retryResult != IDRETRY)
        {
            return false;
        }

        *driverReadyOut = isDriverReady();
        if (*driverReadyOut)
        {
            return true;
        }
        const int warningResult = ::MessageBoxW(
            nullptr,
            L"R0 模式未启用，Cheat Engine 的进程交互无法保证通过 "
            L"KSword 驱动，请小心使用。\n\n是否仍要继续启动？",
            kPluginTitle,
            MB_OKCANCEL | MB_ICONWARNING | MB_DEFBUTTON2 | MB_SETFOREGROUND);
        return warningResult == IDOK;
    }

    std::wstring makeStatusPath()
    {
        std::vector<wchar_t> tempPath(MAX_PATH + 1U, L'\0');
        const DWORD length = ::GetTempPathW(
            static_cast<DWORD>(tempPath.size()),
            tempPath.data());
        if (length == 0U ||
            length >= static_cast<DWORD>(tempPath.size()))
        {
            return {};
        }
        return std::wstring(tempPath.data(), length) +
            L"ksword-ce-bridge-" +
            std::to_wstring(::GetCurrentProcessId()) +
            L".status";
    }

    std::wstring makeSettingsPath()
    {
        wchar_t localAppData[32768]{};
        const DWORD length = ::GetEnvironmentVariableW(L"LOCALAPPDATA", localAppData, _countof(localAppData));
        if (length == 0U || length >= _countof(localAppData)) return {};
        const std::wstring directory = joinPath(localAppData, L"KSword");
        if (!::CreateDirectoryW(directory.c_str(), nullptr) && ::GetLastError() != ERROR_ALREADY_EXISTS) return {};
        return joinPath(directory, L"ce-backend-options.txt");
    }

    std::string readStatusFile(const std::wstring& path)
    {
        std::ifstream input(path, std::ios::binary);
        if (!input)
        {
            return {};
        }
        std::string status;
        std::getline(input, status);
        return status;
    }

    BridgeStatus waitForBridgeStatus(const std::wstring& statusPath, const std::atomic_bool* canceled = nullptr)
    {
        constexpr std::size_t kAttemptCount = 200U;
        for (std::size_t attempt = 0U; attempt < kAttemptCount; ++attempt)
        {
            if (canceled && canceled->load()) return BridgeStatus::timeout;
            const std::string status = readStatusFile(statusPath);
            if (status == "ready")
            {
                return BridgeStatus::ready;
            }
            if (status == "failed")
            {
                return BridgeStatus::failed;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        return BridgeStatus::timeout;
    }

    BridgeStatus launchCheatEngine(
        const std::wstring& pluginDirectory,
        const DWORD targetProcessId,
        DWORD* const cheatEngineProcessIdOut,
        HANDLE* const cheatEngineProcessHandleOut = nullptr,
        std::wstring* const logPathOut = nullptr,
        const std::atomic_bool* canceled = nullptr,
        const DWORD noAttachThreadId = 0U,
        const std::wstring& noAttachMode = {})
    {
        if (cheatEngineProcessIdOut != nullptr)
        {
            *cheatEngineProcessIdOut = 0U;
        }
        if (cheatEngineProcessHandleOut != nullptr)
        {
            *cheatEngineProcessHandleOut = nullptr;
        }
        if (logPathOut != nullptr)
        {
            logPathOut->clear();
        }
        const std::wstring sourceCeDirectory =
            joinPath(pluginDirectory, L"payload\\Cheat Engine");
        const std::wstring bridgeDll = joinPath(
            pluginDirectory,
            L"bridge\\x64\\KswordCheatEnginePlugin.dll");
        if (!verifyPayloadFiles(pluginDirectory))
        {
            return BridgeStatus::launchFailed;
        }
        // 整树硬链接克隆 CE payload，并把主 exe 以随机后缀重命名。
        // bridgeDll 保持原路径（CE 在 autorun 阶段 LoadLibrary 绝对路径加载）。
        auto prepared = ksword::randomized_payload::prepareRandomizedPayload(
            sourceCeDirectory, L"cheatengine-x86_64.exe",
            ksword::randomized_payload::NamingMode::SuffixedPreserveStem);
        if (!prepared.success)
        {
            gLaunchFailureMessage = "Cannot prepare randomized CE payload (" +
                prepared.failureDescription + ", win32=" +
                std::to_string(prepared.lastError) + ").";
            return BridgeStatus::launchFailed;
        }
        // 克隆目录由本函数或 WM_TIMER 退出路径择一清理。记录在 gClonedCeDirectory
        // 直到 CE 进程确实退出后再调 cleanupRandomizedPayload。
        gClonedCeDirectory = prepared.clonedDirectory;
        const std::wstring ceDirectory = prepared.clonedDirectory;
        const std::wstring ceExecutable = prepared.clonedExecutable;
        // 失败前统一回收克隆目录的小工具；调用后清空全局，避免被后续 WM_TIMER 再清一次。
        auto discardClonedPayload = [&]() {
            ksword::randomized_payload::finishRandomizedPayloadLaunch(prepared, nullptr);
            if (!gClonedCeDirectory.empty())
            {
                ksword::randomized_payload::cleanupRandomizedPayload(gClonedCeDirectory);
                gClonedCeDirectory.clear();
            }
        };
        const std::wstring statusPath = makeStatusPath();
        if (statusPath.empty())
        {
            gLaunchFailureMessage = "Cannot obtain the Windows temporary directory for CE bridge status.";
            discardClonedPayload();
            return BridgeStatus::launchFailed;
        }

        (void)::DeleteFileW(statusPath.c_str());
        const std::wstring logPath = statusPath + L".log";
        if (logPathOut != nullptr)
        {
            (void)::DeleteFileW(logPath.c_str());
            *logPathOut = logPath;
        }
        const bool logEnvironmentReady = ::SetEnvironmentVariableW(
                L"KSWORD_CE_LOG_FILE",
                logPath.c_str()) != FALSE &&
            ::SetEnvironmentVariableW(L"KSWORD_DEBUGGER_LOG_FILE", logPath.c_str()) != FALSE;
        const bool controlEnvironmentReady =
            ::SetEnvironmentVariableW(L"KSWORD_CE_CONTROL_FILE", (logPath + L".control").c_str()) != FALSE &&
            ::SetEnvironmentVariableW(L"KSWORD_CE_BACKEND_STATE_FILE", (logPath + L".state").c_str()) != FALSE;
        const std::wstring settingsPath = makeSettingsPath();
        const bool settingsEnvironmentReady = !settingsPath.empty() &&
            ::SetEnvironmentVariableW(L"KSWORD_CE_SETTINGS_FILE", settingsPath.c_str()) != FALSE &&
            ::SetEnvironmentVariableW(L"KSWORD_CE_SETTINGS_TEMP_FILE",
                (settingsPath + L"." + std::to_wstring(::GetCurrentProcessId()) + L".new").c_str()) != FALSE;
        if (!logEnvironmentReady ||
            !controlEnvironmentReady ||
            !settingsEnvironmentReady ||
            ::SetEnvironmentVariableW(
                L"KSWORD_CE_BRIDGE_DLL",
                bridgeDll.c_str()) == FALSE ||
            ::SetEnvironmentVariableW(
                L"KSWORD_CE_BRIDGE_STATUS_FILE",
                statusPath.c_str()) == FALSE ||
            ::SetEnvironmentVariableW(
                L"KSWORD_CE_TARGET_PID",
                std::to_wstring(targetProcessId).c_str()) == FALSE)
        {
            const DWORD error = ::GetLastError();
            gLaunchFailureMessage = windowsFailure(
                "Cannot prepare CE bridge environment", ceExecutable, error);
            discardClonedPayload();
            return BridgeStatus::launchFailed;
        }
        // Opt-in no-attach channel: the CE bridge DLL checks these two
        // variables in its initialize hook and arms IndependentFrontend
        // before the first attach. Both must be set together; a missing
        // value leaves the child on the default attach path.
        if (noAttachThreadId != 0U && !noAttachMode.empty())
        {
            if (::SetEnvironmentVariableW(
                    L"KSWORD_DEBUGGER_NOATTACH_MODE",
                    noAttachMode.c_str()) == FALSE ||
                ::SetEnvironmentVariableW(
                    L"KSWORD_DEBUGGER_NOATTACH_TID",
                    std::to_wstring(noAttachThreadId).c_str()) == FALSE)
            {
                const DWORD error = ::GetLastError();
                gLaunchFailureMessage = windowsFailure(
                    "Cannot propagate KSword no-attach selection to CE",
                    ceExecutable, error);
                discardClonedPayload();
                return BridgeStatus::launchFailed;
            }
        }

        std::wstring commandLine = L"\"" + ceExecutable + L"\"";
        std::vector<wchar_t> mutableCommandLine(
            commandLine.begin(),
            commandLine.end());
        mutableCommandLine.push_back(L'\0');
        STARTUPINFOW startupInfo{};
        startupInfo.cb = sizeof(startupInfo);
        PROCESS_INFORMATION processInformation{};

        const BOOL created = ::CreateProcessW(
            ceExecutable.c_str(),
            mutableCommandLine.data(),
            nullptr,
            nullptr,
            FALSE,
            0U,
            nullptr,
            ceDirectory.c_str(),
            &startupInfo,
            &processInformation);
        if (created == FALSE)
        {
            const DWORD error = ::GetLastError();
            gLaunchFailureMessage = windowsFailure(
                "Cannot start Cheat Engine", ceExecutable, error);
            discardClonedPayload();
            return BridgeStatus::launchFailed;
        }

        ksword::randomized_payload::finishRandomizedPayloadLaunch(
            prepared, processInformation.hProcess);

        if (cheatEngineProcessIdOut != nullptr)
        {
            *cheatEngineProcessIdOut = processInformation.dwProcessId;
        }
        ::CloseHandle(processInformation.hThread);
        if (cheatEngineProcessHandleOut != nullptr)
        {
            *cheatEngineProcessHandleOut = processInformation.hProcess;
        }
        const BridgeStatus status = waitForBridgeStatus(statusPath, canceled);
        if (cheatEngineProcessHandleOut == nullptr)
        {
            ::CloseHandle(processInformation.hProcess);
        }
        (void)::DeleteFileW(statusPath.c_str());
        return status;
    }

    std::string escapeJson(const std::string& value)
    {
        constexpr char hex[] = "0123456789abcdef";
        std::string escaped;
        escaped.reserve(value.size());
        for (const unsigned char character : value)
        {
            switch (character)
            {
            case '"': escaped += "\\\""; break;
            case '\\': escaped += "\\\\"; break;
            case '\b': escaped += "\\b"; break;
            case '\f': escaped += "\\f"; break;
            case '\n': escaped += "\\n"; break;
            case '\r': escaped += "\\r"; break;
            case '\t': escaped += "\\t"; break;
            default:
                if (character < 0x20U)
                {
                    escaped += "\\u00";
                    escaped += hex[character >> 4U];
                    escaped += hex[character & 0x0fU];
                }
                else
                {
                    escaped += static_cast<char>(character);
                }
                break;
            }
        }
        return escaped;
    }

    void appendNativeLog(const std::wstring& line)
    {
        if (!::IsWindow(gLogView))
        {
            return;
        }
        if (::GetWindowTextLengthW(gLogView) > 262144)
        {
            (void)::SetWindowTextW(gLogView, L"");
        }
        const int length = ::GetWindowTextLengthW(gLogView);
        (void)::SendMessageW(gLogView, EM_SETSEL, length, length);
        const std::wstring text = line + L"\r\n";
        (void)::SendMessageW(
            gLogView,
            EM_REPLACESEL,
            FALSE,
            reinterpret_cast<LPARAM>(text.c_str()));
    }

    void forwardLogLine(const std::string& rawLine)
    {
        if (rawLine.empty())
        {
            return;
        }
        const std::string line = rawLine.substr(0U, 4096U);
        int wideLength = ::MultiByteToWideChar(
            CP_UTF8, MB_ERR_INVALID_CHARS, line.data(),
            static_cast<int>(line.size()), nullptr, 0);
        const UINT codePage = wideLength > 0 ? CP_UTF8 : CP_ACP;
        if (wideLength == 0)
        {
            wideLength = ::MultiByteToWideChar(
                codePage, 0U, line.data(),
                static_cast<int>(line.size()), nullptr, 0);
        }
        if (wideLength > 0)
        {
            std::wstring wideLine(static_cast<std::size_t>(wideLength), L'\0');
            (void)::MultiByteToWideChar(
                codePage, codePage == CP_UTF8 ? MB_ERR_INVALID_CHARS : 0U,
                line.data(), static_cast<int>(line.size()),
                wideLine.data(), wideLength);
            appendNativeLog(wideLine);
        }
        emitJsonLine(
            "log",
            "\"source\":\"cheat_engine\",\"message\":\"" +
                escapeJson(line) + "\"");
    }

    void pollBridgeLog()
    {
        if (gLogPath.empty())
        {
            return;
        }
        std::ifstream input(gLogPath, std::ios::binary);
        if (!input)
        {
            return;
        }
        input.seekg(0, std::ios::end);
        const std::streamoff end = input.tellg();
        if (end < 0)
        {
            return;
        }
        if (end < gLogOffset)
        {
            gLogOffset = 0;
            gPendingLogLine.clear();
        }
        constexpr std::streamoff kMaximumRead = 65536;
        if (end - gLogOffset > kMaximumRead)
        {
            gLogOffset = end - kMaximumRead;
            gPendingLogLine.clear();
            appendNativeLog(L"较早的 CE 日志已省略。");
        }
        input.seekg(gLogOffset);
        char buffer[4096];
        while (input && gLogOffset < end)
        {
            const auto remaining = end - gLogOffset;
            const auto request = static_cast<std::streamsize>(
                (std::min)(remaining, static_cast<std::streamoff>(sizeof(buffer))));
            input.read(buffer, request);
            const std::streamsize count = input.gcount();
            if (count <= 0)
            {
                break;
            }
            gLogOffset += count;
            for (std::streamsize index = 0; index < count; ++index)
            {
                const char character = buffer[index];
                if (character == '\n')
                {
                    if (!gPendingLogLine.empty() &&
                        gPendingLogLine.back() == '\r')
                    {
                        gPendingLogLine.pop_back();
                    }
                    forwardLogLine(gPendingLogLine);
                    gPendingLogLine.clear();
                }
                else if (gPendingLogLine.size() < 4096U)
                {
                    gPendingLogLine += character;
                }
            }
        }
    }

    void closeCheatEngineHandle()
    {
        if (gCheatEngineProcess != nullptr)
        {
            ::CloseHandle(gCheatEngineProcess);
            gCheatEngineProcess = nullptr;
        }
    }

    void failTab(
        const HWND window,
        const char* const code,
        const char* const message)
    {
        emitError(code, message);
        gTabExitCode = 2;
        if (::IsWindow(window))
        {
            (void)::DestroyWindow(window);
        }
    }

    LRESULT CALLBACK tabWindowProcedure(
        const HWND window,
        const UINT message,
        const WPARAM wParam,
        const LPARAM lParam)
    {
        if (kAsyncResizeMessage != 0 && message == kAsyncResizeMessage)
        {
            // The host posts a size request; only this window's owner performs
            // SetWindowPos. Read latest native client bounds rather than LPARAM
            // dimensions, so coalescing and DPI changes retain full precision.
            MSG redundant{};
            while (::PeekMessageW(&redundant, window, kAsyncResizeMessage,
                    kAsyncResizeMessage, PM_REMOVE)) {}
            const HWND parent = ::GetParent(window);
            DWORD parentPid = 0;
            ::GetWindowThreadProcessId(parent, &parentPid);
            if (parent != gHostParentWindow || parentPid != gHostProcessId
                || (::GetWindowLongPtrW(window, GWL_STYLE) & WS_CHILD) == 0) return 0;
            RECT bounds{}, current{};
            if (::GetClientRect(parent, &bounds) && ::GetClientRect(window, &current))
            {
                const int width = (std::max)(1L, bounds.right - bounds.left);
                const int height = (std::max)(1L, bounds.bottom - bounds.top);
                if (current.right - current.left != width || current.bottom - current.top != height)
                    ::SetWindowPos(window, nullptr, 0, 0, width, height, SWP_NOZORDER | SWP_NOACTIVATE);
            }
            return 0;
        }
        LRESULT surfaceResult = 0;
        if (ksword::ce_log::message(window, message, wParam, lParam, surfaceResult))
        {
            return surfaceResult;
        }
        switch (message)
        {
        case WM_CREATE:
            gLogView = ksword::ce_log::create(window);
            if (gLogView == nullptr)
            {
                return -1;
            }
            return 0;
        case WM_SIZE:
            if (::IsWindow(gLogView))
            {
                ksword::ce_log::resize(window);
            }
            return 0;
        case WM_SETFOCUS:
            if (::IsWindow(gLogView))
            {
                (void)::SetFocus(gLogView);
            }
            return 0;
        case kInitializeTabMessage:
        {
            bool driverReady = false;
            if (!confirmR0OrWarn(&driverReady))
            {
                failTab(
                    window,
                    "r0_required",
                    "Enable KSword R0 mode and load the driver before launching.");
                return 0;
            }

            if (gTabLaunchTask) return 0;
            auto task = std::make_shared<TabLaunchTask>();
            task->driverReady = driverReady;
            const std::wstring directory = parentDirectory(currentExecutablePath());
            task->worker = std::thread([task, directory]() {
                task->status = launchCheatEngine(directory, 0U, &task->processId,
                    &task->process, &task->logPath, &task->canceled);
                task->failure = gLaunchFailureMessage;
            });
            gTabLaunchTask = std::move(task);
            // Host liveness and window dispatch continue during bridge wait.
            (void)::SetTimer(window, kLifecycleTimerId, 250U, nullptr);
            return 0;
        }
        case WM_TIMER:
            if (wParam == kLifecycleTimerId)
            {
                if (gTabLaunchTask && ::WaitForSingleObject(
                        gTabLaunchTask->worker.native_handle(), 0) == WAIT_OBJECT_0)
                {
                    const auto task = std::move(gTabLaunchTask);
                    task->worker.join(); // Already signaled; no bridge/file wait here.
                    if (task->status == BridgeStatus::launchFailed)
                    {
                        failTab(window, "launch_failed", task->failure.c_str());
                        return 0;
                    }
                    gCheatEngineProcess = task->process;
                    task->process = nullptr;
                    gLogPath = task->logPath;
                    ksword::ce_log::setSession(gLogPath);
                    pollBridgeLog();
                    if (task->status != BridgeStatus::ready)
                    {
                        appendNativeLog(L"KSword 桥接尚未就绪；CE 已独立启动。");
                        emitJsonLine("warning", "\"code\":\"bridge_not_ready\",\"message\":\"KSword bridge did not report ready.\"");
                    }
                    appendNativeLog(L"Cheat Engine PID " + std::to_wstring(task->processId) + L" 已在独立窗口运行。");
                    emitJsonLine("ce_started", "\"cheat_engine_pid\":" + std::to_string(task->processId)
                        + ",\"r0_ready\":" + (task->driverReady ? "true" : "false")
                        + ",\"bridge_ready\":" + (task->status == BridgeStatus::ready ? "true" : "false"));
                }
                pollBridgeLog();
                ksword::ce_log::pollState();
                HANDLE hostProcess = ::OpenProcess(
                    SYNCHRONIZE, FALSE, gHostProcessId);
                const bool hostExited =
                    hostProcess == nullptr ||
                    ::WaitForSingleObject(hostProcess, 0U) == WAIT_OBJECT_0;
                if (hostProcess != nullptr)
                {
                    ::CloseHandle(hostProcess);
                }
                if (hostExited)
                {
                    (void)::DestroyWindow(window);
                    return 0;
                }
                if (gCheatEngineProcess != nullptr &&
                    ::WaitForSingleObject(
                        gCheatEngineProcess, 0U) == WAIT_OBJECT_0)
                {
                    DWORD exitCode = 0U;
                    (void)::GetExitCodeProcess(gCheatEngineProcess, &exitCode);
                    pollBridgeLog();
                    appendNativeLog(
                        L"Cheat Engine 已退出，代码 " +
                        std::to_wstring(exitCode) + L"。");
                    emitJsonLine(
                        "ce_exited",
                        "\"exit_code\":" + std::to_string(exitCode));
                    closeCheatEngineHandle();
                    (void)::DeleteFileW(gLogPath.c_str());
                    (void)::DeleteFileW((gLogPath + L".control").c_str());
                    (void)::DeleteFileW((gLogPath + L".control.new").c_str());
                    (void)::DeleteFileW((gLogPath + L".state").c_str());
                    (void)::DeleteFileW((gLogPath + L".state.new").c_str());
                    gLogPath.clear();
                    ksword::ce_log::setSession(L"");
                    // CE 真正退出后回收随机命名克隆目录；若此前已被清理（启动失败路径）这里是 no-op。
                    if (!gClonedCeDirectory.empty())
                    {
                        ksword::randomized_payload::cleanupRandomizedPayload(gClonedCeDirectory);
                        gClonedCeDirectory.clear();
                    }
                }
            }
            return 0;
        case WM_DESTROY:
            if (gTabLaunchTask) gTabLaunchTask->canceled.store(true);
            (void)::KillTimer(window, kLifecycleTimerId);
            pollBridgeLog();
            closeCheatEngineHandle();
            ksword::ce_log::destroy();
            gLogView = nullptr;
            gTabWindow = nullptr;
            ::PostQuitMessage(gTabExitCode);
            return 0;
        default:
            return ::DefWindowProcW(window, message, wParam, lParam);
        }
    }

    int runTab(const ParsedArguments& arguments)
    {
        WNDCLASSEXW windowClass{};
        windowClass.cbSize = sizeof(windowClass);
        windowClass.lpfnWndProc = tabWindowProcedure;
        windowClass.hInstance = ::GetModuleHandleW(nullptr);
        windowClass.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
        windowClass.hbrBackground =
            reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
        windowClass.lpszClassName = kTabWindowClass;
        if (::RegisterClassExW(&windowClass) == 0U &&
            ::GetLastError() != ERROR_CLASS_ALREADY_EXISTS)
        {
            emitError(
                "window_class_failed",
                "The log forwarding Tab window class could not be registered.");
            return 2;
        }

        gHostProcessId = arguments.hostProcessId;
        gHostParentWindow = arguments.parentWindow;
        gTabExitCode = 0;
        gTabWindow = ::CreateWindowExW(
            WS_EX_CONTROLPARENT,
            kTabWindowClass,
            kPluginTitle,
            WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN | WS_CLIPSIBLINGS,
            0, 0, 1, 1, arguments.parentWindow, nullptr,
            ::GetModuleHandleW(nullptr), nullptr);
        if (gTabWindow == nullptr)
        {
            emitError(
                "tab_window_failed",
                "The log forwarding Tab child window could not be created.");
            return 2;
        }

        emitJsonLine(
            "tab_ready",
            "\"hwnd\":\"" +
                std::to_string(
                    reinterpret_cast<std::uintptr_t>(gTabWindow)) +
                "\",\"resize_async\":\"parent_client_v1\"");
        (void)::PostMessageW(
            gTabWindow, kInitializeTabMessage, 0U, 0);

        MSG message{};
        while (::GetMessageW(&message, nullptr, 0U, 0U) > 0)
        {
            ::TranslateMessage(&message);
            ::DispatchMessageW(&message);
        }
        // The log window is already destroyed. Finish cancellation observation
        // before native process exit, retaining all stack/value dependencies;
        // close only our process handle, never the independent CE/target.
        if (gTabLaunchTask)
        {
            const auto task = std::move(gTabLaunchTask);
            task->canceled.store(true);
            task->worker.join();
        }
        return gTabExitCode;
    }

    int runInfo()
    {
        const bool payloadReady = verifyPayloadFiles(
            parentDirectory(currentExecutablePath()));
        emitJsonLine(
            "info",
            "\"runtime\":\"executable\",\"plugin_type\":\"hybrid\","
            "\"targets\":[\"process\",\"tab\"],"
            "\"commands\":[\"launch\",\"tab\",\"check\",\"info\"],"
            "\"presentation\":\"standalone_with_log_tab\","
            "\"driver_transport\":\"KswordARK\",\"bridge_api\":6,"
            "\"architecture\":\"x64\",\"debugger_backend_api\":1,"
            "\"hvm_switch\":true,\"hvm_protocol_commands\":16,"
            "\"payload_ready\":" + std::string(payloadReady ? "true" : "false") +
            (payloadReady ? "" : ",\"payload_error\":\"" +
                escapeJson(gLaunchFailureMessage) + "\""));
        return 0;
    }

    int runDriverCheck()
    {
        const bool ready = isDriverReady();
        emitJsonLine(
            "driver_status",
            std::string("\"r0_ready\":") + (ready ? "true" : "false"));
        return ready ? 0 : 2;
    }
}

int wmain(const int argc, wchar_t* const argv[])
{
    const ParsedArguments arguments = parseArguments(argc, argv);
    if (!arguments.valid)
    {
        emitError("invalid_arguments", "Invalid KSword plugin arguments.");
        return 64;
    }
    if (arguments.command == L"info")
    {
        return runInfo();
    }
    if (arguments.command == L"check")
    {
        return runDriverCheck();
    }
    if (arguments.command == L"tab")
    {
        return runTab(arguments);
    }

    emitJsonLine(
        "launch_started",
        "\"target_pid\":" + std::to_string(arguments.targetProcessId));
    bool driverReady = false;
    if (!confirmR0OrWarn(&driverReady))
    {
        emitError(
            "r0_required",
            "Enable KSword R0 mode and load the driver before launching.");
        return 2;
    }

    const std::wstring pluginDirectory =
        parentDirectory(currentExecutablePath());
    DWORD cheatEngineProcessId = 0U;
    const BridgeStatus bridgeStatus = launchCheatEngine(
        pluginDirectory,
        arguments.targetProcessId,
        &cheatEngineProcessId,
        nullptr,
        nullptr,
        nullptr,
        arguments.targetThreadId,
        arguments.noAttachMode);
    if (bridgeStatus == BridgeStatus::launchFailed)
    {
        ::MessageBoxW(
            nullptr,
            L"Cheat Engine 插件载荷不完整或无法启动，请重新生成插件文件。",
            kPluginTitle,
            MB_OK | MB_ICONERROR | MB_SETFOREGROUND);
        emitError(
            "launch_failed",
            gLaunchFailureMessage.c_str());
        return 2;
    }
    if (bridgeStatus != BridgeStatus::ready)
    {
        ::MessageBoxW(
            nullptr,
            L"R0 模式未启用或 KSword 桥接初始化失败，进程交互无法保证"
            L"通过 KSword 驱动，请小心使用。",
            kPluginTitle,
            MB_OK | MB_ICONWARNING | MB_SETFOREGROUND);
        emitJsonLine(
            "warning",
            "\"code\":\"bridge_not_ready\","
            "\"message\":\"R0 mode is not enabled; use carefully.\"");
    }

    emitJsonLine(
        "launch_complete",
        "\"target_pid\":" + std::to_string(arguments.targetProcessId) +
        ",\"cheat_engine_pid\":" + std::to_string(cheatEngineProcessId) +
        ",\"r0_ready\":" + (driverReady ? "true" : "false") +
        ",\"bridge_ready\":" +
        (bridgeStatus == BridgeStatus::ready ? "true" : "false"));
    return 0;
}
