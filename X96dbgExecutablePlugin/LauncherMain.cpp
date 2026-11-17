#include "LogSurface.h"
#include "../TitanEnginePlugin/ControlProtocol.h"
#include "../X96dbgIntegration/NavigationClient.h"
#include "../DebuggerBackend/KswordRandomizedPayload.h"
#include <Windows.h>
#include <objbase.h>
#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cwchar>
#include <fstream>
#include <string>
#include <vector>

namespace
{
    constexpr wchar_t kWindowClass[] = L"KSwordX96dbgLogSurface";
    constexpr UINT kStartMessage = WM_APP + 1;
    constexpr UINT_PTR kPollTimer = 1;
    struct Arguments
    {
        std::wstring command, debugger;
        DWORD pid = 0, hostPid = 0, noAttachTid = 0;
        std::wstring noAttachMode; // L"", L"hvm" or L"kernel"
        HWND parent = nullptr;
        std::uint64_t createTime = 0, address = 0;
        ksword::x64dbg_navigation::View view = ksword::x64dbg_navigation::View::Disassembly;
        bool valid = false;
    };
    HWND gWindow = nullptr;
    HANDLE gDebugger = nullptr, gHost = nullptr;
    DWORD gNoAttachTid = 0U;
    std::wstring gNoAttachMode;
    std::wstring gLogPath, gSessionDirectory;
    // 随机命名克隆目录；非空时在调试器退出后一并清理。
    std::wstring gClonedPayloadDirectory;
    std::string gSessionId, gPendingLog;
    std::streamoff gLogOffset = 0;

    std::string utf8(const std::wstring& value)
    {
        const int count = WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
        if (count <= 0) return {};
        std::string result(static_cast<size_t>(count), '\0');
        WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), result.data(), count, nullptr, nullptr);
        return result;
    }
    std::wstring wide(const std::string& value)
    {
        const int count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), nullptr, 0);
        if (count <= 0) return L"[Invalid UTF-8 log line]";
        std::wstring result(static_cast<size_t>(count), L'\0');
        MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), result.data(), count);
        return result;
    }
    std::string json(const std::string& value)
    {
        const char digits[] = "0123456789abcdef";
        std::string result;
        for (unsigned char c : value)
        {
            if (c == '"' || c == '\\') { result += '\\'; result += static_cast<char>(c); }
            else if (c < 32) { result += "\\u00"; result += digits[c >> 4]; result += digits[c & 15]; }
            else result += static_cast<char>(c);
        }
        return result;
    }
    void emit(const char* event, const std::string& fields)
    {
        const std::string line = "{\"protocol\":\"ksword-plugin/1\",\"plugin_id\":\"x96dbg\",\"event\":\"" +
            std::string(event) + "\"" + (fields.empty() ? "" : "," + fields) + "}\n";
        const HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
        if (output != nullptr && output != INVALID_HANDLE_VALUE)
        { DWORD written = 0; (void)WriteFile(output, line.data(), static_cast<DWORD>(line.size()), &written, nullptr); }
    }
    void log(const std::string& line)
    {
        if (line.empty()) return;
        // Never forward malformed UTF-8 into PluginHost's strict JSON parser.
        const std::wstring rendered = wide(line.substr(0, 4096));
        const std::string clipped = utf8(rendered);
        ksword::x96_log::append(rendered);
        emit("log", "\"source\":\"titan_engine\",\"message\":\"" + json(clipped) + "\"");
    }
    std::string failure(const std::string& operation, DWORD error)
    {
        wchar_t message[512]{};
        FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, error, 0, message, _countof(message), nullptr);
        std::wstring detail(message);
        while (!detail.empty() && (detail.back() == L'\r' || detail.back() == L'\n')) detail.pop_back();
        return operation + " (Win32 error " + std::to_string(error) + (detail.empty() ? ")" : ": " + utf8(detail) + ")");
    }
    std::wstring directory()
    {
        std::vector<wchar_t> path(32768);
        const DWORD count = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
        if (count == 0 || count >= path.size()) return {};
        std::wstring result(path.data(), count);
        return result.substr(0, result.find_last_of(L"\\/"));
    }
    bool number(const wchar_t* value, unsigned long long maximum, unsigned long long& output)
    {
        if (value == nullptr || *value == 0 || *value == L'-' || *value == L'+') return false;
        for (const wchar_t* c = value; *c != 0; ++c) if (*c < L'0' || *c > L'9') return false;
        wchar_t* end = nullptr; errno = 0;
        output = std::wcstoull(value, &end, 10);
        return errno == 0 && end != value && *end == 0 && output != 0 && output <= maximum;
    }
    Arguments parse(int argc, wchar_t* argv[])
    {
        Arguments args;
        if (argc < 3 || std::wstring(argv[1]) != L"--ksword-plugin") return args;
        args.command = argv[2];
        if (args.command != L"tab" && args.command != L"attach" && args.command != L"navigate" && args.command != L"check" && args.command != L"info") return args;
        for (int index = 3; index < argc; ++index)
        {
            const std::wstring option = argv[index];
            if (option == L"--") continue;
            if (index + 1 == argc) return args;
            unsigned long long value = 0;
            if (option == L"--pid") { if (!number(argv[++index], MAXDWORD, value)) return args; args.pid = static_cast<DWORD>(value); }
            else if (option == L"--create-time") { if (!number(argv[++index], UINT64_MAX, value)) return args; args.createTime = value; }
            else if (option == L"--address")
            { const auto argument = argv[++index]; if (std::wstring(argument) != L"0" && !number(argument, UINT64_MAX, value)) return args; args.address = value; }
            else if (option == L"--view")
            { const std::wstring view(argv[++index]); if (view != L"cpu" && view != L"dump") return args; args.view = view == L"dump" ? ksword::x64dbg_navigation::View::Dump : ksword::x64dbg_navigation::View::Disassembly; }
            else if (option == L"--debugger") args.debugger = argv[++index];
            else if (option == L"--host-pid") { if (!number(argv[++index], MAXDWORD, value)) return args; args.hostPid = static_cast<DWORD>(value); }
            else if (option == L"--parent-hwnd") { if (!number(argv[++index], UINTPTR_MAX, value)) return args; args.parent = reinterpret_cast<HWND>(static_cast<std::uintptr_t>(value)); }
            else if (option == L"--target-kind") { if (std::wstring(argv[++index]) != L"process") return args; }
            else if (option == L"--tid") { if (!number(argv[++index], MAXDWORD, value)) return args; args.noAttachTid = static_cast<DWORD>(value); }
            else if (option == L"--noattach-mode")
            {
                const std::wstring mode(argv[++index]);
                if (mode != L"hvm" && mode != L"kernel") return args;
                args.noAttachMode = mode;
            }
            else if (option == L"--path" || option == L"--process-name") ++index;
            else return args;
        }
        if (args.command == L"tab")
        {
            DWORD owner = 0;
            args.valid = args.parent != nullptr && args.hostPid != 0 && IsWindow(args.parent) &&
                GetWindowThreadProcessId(args.parent, &owner) != 0 && owner == args.hostPid && args.pid == 0;
        }
        else args.valid = args.parent == nullptr && args.hostPid == 0 && ((args.command == L"attach" || args.command == L"navigate") ? args.pid != 0 : args.pid == 0)
            && (args.command != L"navigate" || args.createTime != 0)
            && (args.command == L"navigate" || (args.createTime == 0 && args.address == 0 && args.debugger.empty()));
        // No-attach selection is optional; both parts must match when supplied.
        if (args.valid && (args.noAttachTid != 0U) != !args.noAttachMode.empty()) args.valid = false;
        return args;
    }
    bool amd64(const std::wstring& path, std::string& error)
    {
        std::ifstream stream(path.c_str(), std::ios::binary);
        IMAGE_DOS_HEADER dos{}; DWORD signature = 0; IMAGE_FILE_HEADER header{};
        if (!stream.read(reinterpret_cast<char*>(&dos), sizeof(dos)) || dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew < static_cast<LONG>(sizeof(dos)))
        { error = "Missing or invalid x64 PE: " + utf8(path); return false; }
        stream.seekg(dos.e_lfanew);
        if (!stream.read(reinterpret_cast<char*>(&signature), sizeof(signature)) || signature != IMAGE_NT_SIGNATURE ||
            !stream.read(reinterpret_cast<char*>(&header), sizeof(header)) || header.Machine != IMAGE_FILE_MACHINE_AMD64)
        { error = "Only AMD64 payloads are supported: " + utf8(path); return false; }
        return true;
    }
    bool payload(std::string& error)
    {
        const std::wstring root = directory() + L"\\payload\\x64dbg\\";
        for (const auto file : {L"x64dbg.exe", L"x64dbg.dll", L"x64gui.dll", L"x64bridge.dll", L"TitanEngine.dll", L"KSword\\TitanEngine.dll"})
            if (!amd64(root + file, error)) return false;
        return true;
    }
    bool session(std::string& error, bool kswordEngine = true)
    {
        GUID id{};
        if (FAILED(CoCreateGuid(&id))) { error = "Cannot allocate a debugger session identity."; return false; }
        wchar_t token[40]{};
        if (StringFromGUID2(id, token, _countof(token)) == 0) { error = "Cannot format the debugger session identity."; return false; }
        std::wstring value(token);
        gSessionId = utf8(value.substr(1, value.size() - 2));
        const std::wstring sessions = directory() + L"\\sessions";
        if (!CreateDirectoryW(sessions.c_str(), nullptr) && GetLastError() != ERROR_ALREADY_EXISTS)
        { error = failure("Cannot create debugger session directory", GetLastError()); return false; }
        gSessionDirectory = sessions + L"\\" + value.substr(1, value.size() - 2);
        if (!CreateDirectoryW(gSessionDirectory.c_str(), nullptr))
        { error = failure("Cannot create isolated debugger user directory", GetLastError()); return false; }
        // Canonical PR #3974 uses the user directory INI before checked engine loading.
        // The narrow KSword core patch reserves DEBUG_ENGINE value 4.
        std::ofstream ini((gSessionDirectory + L"\\x64dbg.ini").c_str(), std::ios::binary | std::ios::trunc);
        ini << "[Engine]\r\nDebugEngine=" << (kswordEngine ? 4 : 0) << "\r\n[Events]\r\nSystemBreakpoint=1\r\n"; ini.close();
        if (!ini) { error = "Cannot write isolated debugger engine selection."; return false; }
        gLogPath = gSessionDirectory + L"\\backend.log";
        std::ofstream empty(gLogPath.c_str(), std::ios::binary | std::ios::trunc);
        if (!empty) { error = "Cannot create debugger session log: " + utf8(gLogPath); return false; }
        auto options = ksword::titan::control::defaults();
        std::ifstream preferences((directory() + L"\\x96dbg-options.ini").c_str(), std::ios::binary);
        std::string packet;
        if (preferences && (!std::getline(preferences, packet) || !ksword::titan::control::preferences(packet, options)))
            empty << "Invalid saved x96dbg policy; using documented normal defaults.\n";
        empty.close();
        // Persist options, never HVM activation. The proxy applies this packet
        // outside DllMain and publishes an actual-state ACK before UI changes.
        std::ofstream control((gLogPath + L".control").c_str(), std::ios::binary | std::ios::trunc);
        control << ksword::titan::control::request(gSessionId, 1, 0, options); control.close();
        if (!control) { error = "Cannot write initial debugger policy request."; return false; }
        return true;
    }
    std::vector<wchar_t> environment(bool freshAttach = false)
    {
        std::vector<std::wstring> entries;
        LPWCH inherited = GetEnvironmentStringsW();
        if (inherited != nullptr)
        {
            for (const wchar_t* p = inherited; *p != 0; p += std::wcslen(p) + 1)
            {
                if (_wcsnicmp(p, L"KSWORD_DEBUGGER_", 16) != 0 && _wcsnicmp(p, L"KSWORD_NAVIGATION_", 18) != 0) entries.emplace_back(p);
            }
            FreeEnvironmentStringsW(inherited);
        }
        const std::wstring sessionId(gSessionId.begin(), gSessionId.end());
        entries.push_back(L"KSWORD_DEBUGGER_LOG_FILE=" + gLogPath);
        entries.push_back(L"KSWORD_DEBUGGER_CONTROL_FILE=" + gLogPath + L".control");
        entries.push_back(L"KSWORD_DEBUGGER_STATE_FILE=" + gLogPath + L".state");
        entries.push_back(L"KSWORD_DEBUGGER_SESSION_ID=" + sessionId);
        if (gNoAttachTid != 0U && !gNoAttachMode.empty())
        {
            entries.push_back(L"KSWORD_DEBUGGER_NOATTACH_MODE=" + gNoAttachMode);
            entries.push_back(L"KSWORD_DEBUGGER_NOATTACH_TID=" + std::to_wstring(gNoAttachTid));
        }
        if (freshAttach) entries.push_back(L"KSWORD_NAVIGATION_FRESH_ATTACH=1");
        std::sort(entries.begin(), entries.end(), [](const auto& a, const auto& b) { return _wcsicmp(a.c_str(), b.c_str()) < 0; });
        std::vector<wchar_t> block;
        for (const auto& entry : entries) { block.insert(block.end(), entry.begin(), entry.end()); block.push_back(0); }
        block.push_back(0); return block;
    }
    bool launch(DWORD pid, DWORD& debuggerPid, std::string& error, const std::wstring& selectedDebugger = L"", bool freshNavigation = false)
    {
        if ((selectedDebugger.empty() && !payload(error)) || !session(error, selectedDebugger.empty())) return false;
        // 使用自带 payload 的分支：整树硬链接克隆到会话专用目录并随机重命名主 exe，
        // 让进程名/路径对按名匹配的反作弊和日志呈现为陌生身份；用户外挂的 debugger 保留原路径。
        std::wstring exe;
        std::wstring root;
        ksword::randomized_payload::PrepareResult prepared;
        if (selectedDebugger.empty()) {
            const std::wstring sourceRoot = directory() + L"\\payload\\x64dbg";
            prepared = ksword::randomized_payload::prepareRandomizedPayload(
                sourceRoot, L"x64dbg.exe",
                ksword::randomized_payload::NamingMode::SuffixedPreserveStem);
            if (!prepared.success) {
                error = failure(("Cannot prepare randomized payload (" + prepared.failureDescription + ")").c_str(), prepared.lastError);
                return false;
            }
            gClonedPayloadDirectory = prepared.clonedDirectory;
            exe = prepared.clonedExecutable;
            root = prepared.clonedDirectory;
        } else {
            exe = selectedDebugger;
            root = exe.substr(0, exe.find_last_of(L"\\/"));
        }
        std::wstring command = L"\"" + exe + L"\" -userdir \"" + gSessionDirectory + L"\"";
        if (pid != 0) command += L" -p " + std::to_wstring(pid);
        std::vector<wchar_t> mutableCommand(command.begin(), command.end()); mutableCommand.push_back(0);
        auto block = environment(freshNavigation);
        STARTUPINFOW startup{}; startup.cb = sizeof(startup);
        PROCESS_INFORMATION process{};
        if (!CreateProcessW(exe.c_str(), mutableCommand.data(), nullptr, nullptr, FALSE,
            CREATE_UNICODE_ENVIRONMENT | CREATE_NEW_PROCESS_GROUP, block.data(), root.c_str(), &startup, &process))
        {
            error = failure("Cannot start standalone x64dbg", GetLastError());
            ksword::randomized_payload::finishRandomizedPayloadLaunch(prepared, nullptr);
            // 启动失败则立即回收刚刚克隆的目录，避免遗留在 LocalAppData 下。
            if (!gClonedPayloadDirectory.empty()) {
                ksword::randomized_payload::cleanupRandomizedPayload(gClonedPayloadDirectory);
                gClonedPayloadDirectory.clear();
            }
            return false;
        }
        ksword::randomized_payload::finishRandomizedPayloadLaunch(prepared, process.hProcess);
        CloseHandle(process.hThread); gDebugger = process.hProcess; debuggerPid = process.dwProcessId;
        return true;
    }
    WORD machine(const std::wstring& path)
    {
        std::ifstream stream(path.c_str(), std::ios::binary);
        IMAGE_DOS_HEADER dos{}; DWORD signature = 0; IMAGE_FILE_HEADER header{};
        if (!stream.read(reinterpret_cast<char*>(&dos), sizeof(dos)) || dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew < static_cast<LONG>(sizeof(dos))) return 0;
        stream.seekg(dos.e_lfanew);
        if (!stream.read(reinterpret_cast<char*>(&signature), sizeof(signature)) || signature != IMAGE_NT_SIGNATURE
            || !stream.read(reinterpret_cast<char*>(&header), sizeof(header))) return 0;
        return header.Machine;
    }
    int navigation(const Arguments& args)
    {
        using namespace ksword::x64dbg_navigation;
        const HANDLE target = OpenProcess(PROCESS_QUERY_INFORMATION | SYNCHRONIZE, FALSE, args.pid);
        if (target == nullptr)
        { emit("error", "\"code\":\"target_unavailable\",\"win32_error\":" + std::to_string(GetLastError())); return 2; }
        auto fail = [&](const char* code, DWORD error)
        { emit("error", "\"code\":\"" + std::string(code) + "\",\"win32_error\":" + std::to_string(error)); CloseHandle(target); return 2; };
        if (creationTime(target) != args.createTime || WaitForSingleObject(target, 0) != WAIT_TIMEOUT)
            return fail("target_changed", ERROR_INVALID_STATE);
        // Cross-host repeated clicks serialize only their own target. We never
        // close a debugger to make space or retry an uncertain attachment.
        const std::wstring lockName = L"Local\\KSword.X64Dbg.Navigation." + std::to_wstring(args.pid) + L"." + std::to_wstring(args.createTime);
        const HANDLE launchLock = CreateMutexW(nullptr, FALSE, lockName.c_str());
        if (launchLock == nullptr) return fail("navigation_lock_failed", GetLastError());
        const DWORD wait = WaitForSingleObject(launchLock, 15000);
        if (wait != WAIT_OBJECT_0 && wait != WAIT_ABANDONED)
        { CloseHandle(launchLock); return fail("navigation_busy", ERROR_BUSY); }
        struct MutexLease { HANDLE value; ~MutexLease() { ReleaseMutex(value); CloseHandle(value); } } lease{launchLock};
        Request request{};
        request.operation = Operation::Navigate; request.targetPid = args.pid; request.targetCreateTime = args.createTime;
        request.address = args.address; request.view = args.view; request.requestId = GetTickCount64() ^ (static_cast<std::uint64_t>(GetCurrentProcessId()) << 32);
        if (request.requestId == 0) request.requestId = 1;
        DWORD debuggerPid = 0; HANDLE debuggerIdentity = nullptr;
        bool reused = findSession(request, debuggerPid, debuggerIdentity) == ERROR_SUCCESS;
        if (!reused)
        {
            BOOL alreadyDebugged = FALSE;
            if (!CheckRemoteDebuggerPresent(target, &alreadyDebugged)) return fail("debugger_owner_unknown", GetLastError());
            if (alreadyDebugged) return fail("target_already_debugged_without_bridge", ERROR_BUSY);
            BOOL wow64 = FALSE;
            if (!IsWow64Process(target, &wow64)) return fail("target_architecture_unknown", GetLastError());
            const WORD architecture = wow64 ? IMAGE_FILE_MACHINE_I386 : IMAGE_FILE_MACHINE_AMD64;
            std::wstring executable = args.debugger;
            if (executable.empty())
            {
                if (wow64) return fail("x32dbg_not_configured", ERROR_FILE_NOT_FOUND);
                executable = directory() + L"\\payload\\x64dbg\\x64dbg.exe";
            }
            else if (machine(executable) != architecture)
            {
                const auto parent = executable.substr(0, executable.find_last_of(L"\\/"));
                const auto outer = parent.substr(0, parent.find_last_of(L"\\/"));
                const std::wstring name = wow64 ? L"x32dbg.exe" : L"x64dbg.exe";
                const std::wstring folder = wow64 ? L"x32" : L"x64";
                for (const auto& candidate : {parent + L"\\" + name, outer + L"\\" + folder + L"\\" + name})
                    if (machine(candidate) == architecture) { executable = candidate; break; }
            }
            if (machine(executable) != architecture) return fail("debugger_architecture_mismatch", ERROR_BAD_EXE_FORMAT);
            const auto root = executable.substr(0, executable.find_last_of(L"\\/"));
            if (machine(root + L"\\plugins\\KSwordNavigation." + (wow64 ? L"dp32" : L"dp64")) != architecture)
                return fail("navigation_bridge_missing", ERROR_MOD_NOT_FOUND);
            if (creationTime(target) != args.createTime || WaitForSingleObject(target, 0) != WAIT_TIMEOUT)
                return fail("target_changed", ERROR_INVALID_STATE);
            std::string error;
            // Bundled mode still performs its original checked payload and KSword
            // engine selection; a selected standard installation stays native.
            const std::wstring selected = args.debugger.empty() ? L"" : executable;
            if (!launch(args.pid, debuggerPid, error, selected, true))
            { emit("error", "\"code\":\"launch_failed\",\"message\":\"" + json(error) + "\""); CloseHandle(target); return 2; }
            debuggerIdentity = gDebugger; gDebugger = nullptr;
        }
        struct Observer { HANDLE value; ~Observer() { CloseHandle(value); } } observer{debuggerIdentity};
        DWORD error = ERROR_TIMEOUT;
        Response response{};
        const auto deadline = GetTickCount64() + 15000;
        if (!reused)
        {
            do
            {
                if (WaitForSingleObject(target, 0) != WAIT_TIMEOUT || WaitForSingleObject(debuggerIdentity, 0) != WAIT_TIMEOUT)
                { error = ERROR_INVALID_STATE; break; }
                Request query = request; query.operation = Operation::Query;
                Response state{};
                const DWORD result = exchange(debuggerPid, debuggerIdentity, query, state, 500);
                if (result == ERROR_SUCCESS && state.targetPid == args.pid && state.targetCreateTime == args.createTime
                    && (state.flags & AttachReady) && !(state.flags & Running))
                { error = ERROR_SUCCESS; break; }
                // Poll only this newly created instance. Never send it another
                // attach or a Run command after errors or missing ACKs.
                Sleep(100);
            } while (GetTickCount64() < deadline);
        }
        else error = ERROR_SUCCESS;
        if (error == ERROR_SUCCESS) error = exchange(debuggerPid, debuggerIdentity, request, response);
        if (error != ERROR_SUCCESS) return fail("navigation_not_confirmed", error);
        if (response.targetPid != args.pid || response.targetCreateTime != args.createTime
            || (args.address != 0 && response.actualAddress != args.address)) return fail("navigation_identity_mismatch", ERROR_INVALID_DATA);
        emit("navigation_complete", "\"debugger_pid\":" + std::to_string(debuggerPid)
            + ",\"target_pid\":" + std::to_string(response.targetPid) + ",\"create_time\":\"" + std::to_string(response.targetCreateTime)
            + "\",\"address\":\"" + std::to_string(response.actualAddress) + "\",\"running\":"
            + ((response.flags & Running) ? "true" : "false") + ",\"reused\":" + (reused ? "true" : "false"));
        CloseHandle(target); return 0;
    }
    void pollLog()
    {
        if (gLogPath.empty()) return;
        std::ifstream stream(gLogPath.c_str(), std::ios::binary);
        if (!stream) return;
        stream.seekg(0, std::ios::end); const auto end = stream.tellg();
        if (end < 0) return;
        if (end < gLogOffset) { gLogOffset = 0; gPendingLog.clear(); }
        if (end - gLogOffset > 65536) { gLogOffset = end - std::streamoff(65536); gPendingLog.clear(); log("Older debugger log entries omitted."); }
        stream.seekg(gLogOffset);
        char data[4096];
        while (stream && gLogOffset < end)
        {
            stream.read(data, static_cast<std::streamsize>((std::min)(end - std::streampos(gLogOffset), std::streamoff(sizeof(data)))));
            const auto count = stream.gcount(); if (count <= 0) break; gLogOffset += count;
            for (std::streamsize i = 0; i < count; ++i)
            {
                if (data[i] == '\n')
                { if (!gPendingLog.empty() && gPendingLog.back() == '\r') gPendingLog.pop_back(); log(gPendingLog); gPendingLog.clear(); }
                else if (gPendingLog.size() < 4096) gPendingLog += data[i];
            }
        }
    }
    void closeHandle(HANDLE& handle) { if (handle != nullptr) { CloseHandle(handle); handle = nullptr; } }
    void removeSessionFiles()
    {
        if (gLogPath.empty()) return;
        for (const auto suffix : {L"", L".control", L".control.new", L".state", L".state.new"}) DeleteFileW((gLogPath + suffix).c_str());
        gLogPath.clear(); gSessionId.clear(); gLogOffset = 0; gPendingLog.clear();
    }
    LRESULT CALLBACK procedure(HWND window, UINT message, WPARAM wParam, LPARAM lParam)
    {
        LRESULT result = 0;
        if (ksword::x96_log::message(window, message, wParam, lParam, result)) return result;
        switch (message)
        {
        case WM_CREATE: return ksword::x96_log::create(window) == nullptr ? -1 : 0;
        case WM_SIZE: ksword::x96_log::resize(window); return 0;
        case kStartMessage:
        {
            DWORD pid = 0; std::string error;
            if (!launch(0, pid, error))
            { log(error); ksword::x96_log::setStatus(wide(error)); emit("warning", "\"code\":\"launch_failed\",\"message\":\"" + json(error) + "\""); }
            else { ksword::x96_log::setSession(gLogPath, gSessionId, directory() + L"\\x96dbg-options.ini"); log("Standalone x64dbg PID " + std::to_string(pid) + " started using the KSword engine."); emit("debugger_started", "\"debugger_pid\":" + std::to_string(pid)); }
            SetTimer(window, kPollTimer, 200, nullptr); return 0;
        }
        case WM_TIMER:
            if (wParam != kPollTimer) return 0;
            if (gHost == nullptr || WaitForSingleObject(gHost, 0) == WAIT_OBJECT_0) { DestroyWindow(window); return 0; }
            pollLog(); ksword::x96_log::pollState();
            if (gDebugger != nullptr && WaitForSingleObject(gDebugger, 0) == WAIT_OBJECT_0)
            {
                DWORD exitCode = 0; GetExitCodeProcess(gDebugger, &exitCode);
                pollLog(); log("x64dbg exited, code " + std::to_string(exitCode) + ".");
                emit("debugger_exited", "\"exit_code\":" + std::to_string(exitCode));
                closeHandle(gDebugger); removeSessionFiles(); ksword::x96_log::setSession(L"", "");
                // 调试器正常退出后回收克隆的 payload 目录。
                if (!gClonedPayloadDirectory.empty()) {
                    ksword::randomized_payload::cleanupRandomizedPayload(gClonedPayloadDirectory);
                    gClonedPayloadDirectory.clear();
                }
            }
            return 0;
        case WM_DESTROY:
            KillTimer(window, kPollTimer); pollLog();
            // Closing the Tab releases observer handles. It never terminates the debugger.
            closeHandle(gDebugger); closeHandle(gHost); ksword::x96_log::destroy(); gWindow = nullptr;
            // 关闭 Tab 不会杀死调试器，所以这里不清理克隆目录——留给调试器自己退出路径处理。
            PostQuitMessage(0); return 0;
        default: return DefWindowProcW(window, message, wParam, lParam);
        }
    }
    int tab(const Arguments& args)
    {
        gHost = OpenProcess(SYNCHRONIZE, FALSE, args.hostPid);
        if (gHost == nullptr) { emit("error", "\"message\":\"Cannot observe the KSword host process.\""); return 2; }
        WNDCLASSEXW windowClass{}; windowClass.cbSize = sizeof(windowClass);
        windowClass.lpfnWndProc = procedure; windowClass.hInstance = GetModuleHandleW(nullptr);
        windowClass.hCursor = LoadCursorW(nullptr, IDC_ARROW); windowClass.lpszClassName = kWindowClass;
        if (RegisterClassExW(&windowClass) == 0 && GetLastError() != ERROR_CLASS_ALREADY_EXISTS)
        { closeHandle(gHost); emit("error", "\"message\":\"Cannot register the Tab window class.\""); return 2; }
        gWindow = CreateWindowExW(WS_EX_CONTROLPARENT, kWindowClass, L"KSword x96dbg",
            WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN | WS_CLIPSIBLINGS, 0, 0, 1, 1,
            args.parent, nullptr, GetModuleHandleW(nullptr), nullptr);
        if (gWindow == nullptr) { closeHandle(gHost); ksword::x96_log::destroy(); emit("error", "\"message\":\"Cannot create the Tab child window.\""); return 2; }
        emit("tab_ready", "\"hwnd\":\"" + std::to_string(reinterpret_cast<std::uintptr_t>(gWindow)) + "\"");
        PostMessageW(gWindow, kStartMessage, 0, 0);
        MSG message{}; int result = 0;
        while ((result = static_cast<int>(GetMessageW(&message, nullptr, 0, 0))) > 0)
        { if (!IsDialogMessageW(gWindow, &message)) { TranslateMessage(&message); DispatchMessageW(&message); } }
        return result == -1 ? 2 : 0;
    }
}

int wmain(int argc, wchar_t* argv[])
{
    const auto args = parse(argc, argv);
    if (!args.valid) { emit("error", "\"code\":\"invalid_arguments\",\"message\":\"Expected --ksword-plugin info|check|attach|navigate|tab with valid target/host arguments.\""); return 2; }
    // Propagate the no-attach selection into the child env block built by
    // environment(). gNoAttachMode stays empty when the caller omits the
    // option, leaving the default attach path untouched.
    gNoAttachTid = args.noAttachTid;
    gNoAttachMode = args.noAttachMode;
    if (args.command == L"tab") return tab(args);
    if (args.command == L"navigate") return navigation(args);
    if (args.command == L"attach")
    {
        auto request = args;
        const HANDLE identity = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, args.pid);
        request.createTime = ksword::x64dbg_navigation::creationTime(identity);
        if (identity != nullptr) CloseHandle(identity);
        if (request.createTime == 0) { emit("error", "\"code\":\"target_unavailable\",\"win32_error\":" + std::to_string(ERROR_INVALID_STATE)); return 2; }
        return navigation(request);
    }
    std::string error;
    if (args.command == L"info" || args.command == L"check")
    {
        const bool ready = payload(error);
        emit(args.command == L"info" ? "info" : "check", "\"architecture\":\"x64\",\"plugin_type\":\"hybrid\",\"targets\":[\"process\",\"tab\"],\"presentation\":\"standalone_with_control_log_tab\",\"engine\":\"ksword\",\"native_without_driver\":true,\"hvm_switch\":true,\"payload_ready\":" +
            std::string(ready ? "true" : "false") + ",\"message\":\"" + json(error) + "\"");
        return args.command == L"info" || ready ? 0 : 2;
    }
    return 2;
}
