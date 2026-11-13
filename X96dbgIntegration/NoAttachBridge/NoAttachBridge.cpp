#include <Windows.h>
#include "../../DebuggerBackend/KswordDebuggerApi.h"
#include "../../shared/driver/KswordArkHvmNoAttachIoctl.h"
#include <array>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <string>

// This is a separate control plugin, not a replacement Titan DebugLoop. Native
// F7/F9 and native attach retain their documented x64dbg meaning.
namespace
{
    struct PluginInit { int pluginHandle, sdkVersion, pluginVersion; char pluginName[256]; };
    using Command = bool (*)(int, char**);
    using Call = unsigned long (__stdcall*)(KSWORD_DEBUGGER_CALL*);
    struct Api
    {
        bool (*registerCommand)(int, const char*, Command, bool) = nullptr;
        bool (*unregisterCommand)(int, const char*) = nullptr;
        void (*log)(const char*) = nullptr;
        bool (*debugging)() = nullptr;
    } api;
    std::recursive_mutex mutex;
    HMODULE backendModule = nullptr;
    Call backendCall = nullptr;
    int pluginHandle = 0;
    bool uncertainOwner = false;
    std::uint64_t session = 0, stop = 0;
    const std::array<const char*, 10> commands{{"ksna_open", "ksna_query", "ksna_pause", "ksna_step", "ksna_run",
        "ksna_close", "ksna_bp", "ksna_bc", "ksna_runto", "ksna_set"}};

    template<class T> bool resolve(HMODULE module, const char* name, T& output)
    {
        const auto address = module ? GetProcAddress(module, name) : nullptr;
        static_assert(sizeof(address) == sizeof(output), "Function pointer ABI");
        std::memcpy(&output, &address, sizeof(output));
        return output != nullptr;
    }
    bool loadBackend()
    {
        if (backendCall) return true;
        wchar_t path[32768]{};
        const DWORD length = GetModuleFileNameW(nullptr, path, _countof(path));
        if (!length || length >= _countof(path)) return false;
        std::wstring directory(path, length);
        const auto slash = directory.find_last_of(L"\\/");
        if (slash == std::wstring::npos) return false;
        directory.resize(slash + 1);
        directory += L"KSword\\TitanEngine.dll";
        // Load only the bundled proxy from the explicit executable-relative path.
        backendModule = LoadLibraryExW(directory.c_str(), nullptr,
            LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
        if (!resolve(backendModule, "KSwordDebuggerCall", backendCall))
        { if (backendModule) FreeLibrary(backendModule); backendModule = nullptr; return false; }
        return true;
    }
    bool number(const char* text, unsigned int radix, std::uint64_t& result)
    {
        if (!text || !*text || *text == '-') return false;
        char* end = nullptr;
        errno = 0;
        result = std::strtoull(text, &end, static_cast<int>(radix));
        return errno == 0 && end != text && *end == '\0';
    }
    bool send(KSWORD_ARK_HVM_NOATTACH_REQUEST request)
    {
        if (!loadBackend()) { api.log("KSword no-attach backend is missing from KSword/TitanEngine.dll"); return false; }
        request.version = KSWORD_ARK_HVM_NOATTACH_VERSION; request.size = sizeof(request);
        request.sessionId = session; request.stopId = stop;
        if (request.operation == KSWORD_ARK_HVM_NOATTACH_OPEN) uncertainOwner = true;
        KSWORD_ARK_HVM_NOATTACH_RESPONSE response{};
        KSWORD_DEBUGGER_CALL call{KSWORD_DEBUGGER_API_VERSION, sizeof(call), KSWORD_DEBUGGER_NOATTACH, 0,
            reinterpret_cast<std::uintptr_t>(&request), reinterpret_cast<std::uintptr_t>(&response),
            sizeof(request), sizeof(response), 0, 0};
        const DWORD transport = backendCall(&call);
        if (transport || call.error || call.bytesReturned != sizeof(response) ||
            response.version != KSWORD_ARK_HVM_NOATTACH_VERSION || response.size != sizeof(response) ||
            response.state > KSWORD_ARK_HVM_NOATTACH_CONTEXT_PENDING || response.breakpointCount > 8)
        {
            char text[128]{}; sprintf_s(text, "KSword no-attach transport failed: %lu; QUERY/CLOSE retains recovery ownership", transport ? transport : call.error);
            api.log(text); stop = 0; return false;
        }
        if (response.sessionId) session = response.sessionId;
        if (response.status >= 0 && response.state == KSWORD_ARK_HVM_NOATTACH_CLOSED && !response.sessionId)
        { uncertainOwner = false; session = 0; }
        stop = response.status >= 0 && response.state == KSWORD_ARK_HVM_NOATTACH_STOPPED ? response.stopId : 0;
        char text[384]{};
        sprintf_s(text, "KSword no-attach: NTSTATUS=%08lX state=%lu PID=%lu TID=%lu session=%llu stop=%llu capabilities=%lX",
            static_cast<unsigned long>(response.status), response.state, response.processId, response.threadId,
            response.sessionId, stop, response.capabilities);
        api.log(text);
        if (stop)
        {
            sprintf_s(text, "Current stop: reason=%lu breakpoint=%lu RIP=%016llX RSP=%016llX RFLAGS=%llX RAX=%016llX (GPR only)",
                response.stopReason, response.breakpointId, response.rip, response.rsp, response.rflags, response.rax);
            api.log(text);
        }
        for (unsigned long i = 0; i < response.breakpointCount; ++i)
        {
            const auto& bp = response.breakpoints[i];
            sprintf_s(text, "EPT breakpoint id=%lu address=%016llX flags=%lX backing=%llX", bp.id, bp.address, bp.flags, bp.physicalPage);
            api.log(text);
        }
        return response.status >= 0;
    }
    bool command(int argc, char** argv)
    {
        std::lock_guard<std::recursive_mutex> lock(mutex);
        if (argc < 1 || !argv || !argv[0]) return false;
        const std::string name(argv[0]);
        KSWORD_ARK_HVM_NOATTACH_REQUEST request{};
        std::uint64_t value = 0, extra = 0;
        if (name == "ksna_open")
        {
            if ((argc != 4 && argc != 5) || std::strcmp(argv[3], "confirm") != 0 || api.debugging() ||
                session || uncertainOwner || !number(argv[1], 10, value) || !number(argv[2], 10, extra) ||
                value > MAXDWORD || extra > MAXDWORD || (argc == 5 && std::strcmp(argv[4], "nested") != 0))
            { api.log("Usage: ksna_open decimalPID, decimalTID, confirm [, nested]; close any native debug session first"); return false; }
            request.operation = KSWORD_ARK_HVM_NOATTACH_OPEN;
            request.processId = static_cast<unsigned long>(value); request.threadId = static_cast<unsigned long>(extra);
            request.flags = KSWORD_ARK_HVM_NOATTACH_CONFIRMED | (argc == 5 ? KSWORD_ARK_HVM_NOATTACH_ALLOW_NESTED : 0UL);
        }
        else if (name == "ksna_query") request.operation = KSWORD_ARK_HVM_NOATTACH_QUERY;
        else if (name == "ksna_pause") request.operation = KSWORD_ARK_HVM_NOATTACH_PAUSE;
        else if (name == "ksna_step") request.operation = KSWORD_ARK_HVM_NOATTACH_STEP;
        else if (name == "ksna_run") request.operation = KSWORD_ARK_HVM_NOATTACH_CONTINUE;
        else if (name == "ksna_close") request.operation = KSWORD_ARK_HVM_NOATTACH_CLOSE;
        else if (name == "ksna_set")
        {
            if (argc != 3 || !number(argv[1], 10, value) || value >= 17 || !number(argv[2], 16, extra))
            { api.log("Usage: ksna_set decimalRegisterIndex, hexValue; GPR order 0=RAX .. 14=R15, 15=RIP, 16=RSP"); return false; }
            request.operation = KSWORD_ARK_HVM_NOATTACH_SET_GPR; request.registerMask = 1ULL << value;
            std::memcpy(reinterpret_cast<unsigned char*>(&request.registers) + value * sizeof(extra), &extra, sizeof(extra));
        }
        else
        {
            if (argc != 2 || !number(argv[1], name == "ksna_bc" ? 10U : 16U, value))
            { api.log("Usage: ksna_bp hexAddress | ksna_bc decimalID | ksna_runto hexAddress"); return false; }
            if (name == "ksna_bp") { request.operation = KSWORD_ARK_HVM_NOATTACH_ADD_BREAKPOINT; request.address = value; }
            else if (name == "ksna_bc" && value <= MAXDWORD)
            { request.operation = KSWORD_ARK_HVM_NOATTACH_REMOVE_BREAKPOINT; request.breakpointId = static_cast<unsigned long>(value); }
            else if (name == "ksna_runto") { request.operation = KSWORD_ARK_HVM_NOATTACH_RUN_TO; request.address = value; }
            else return false;
        }
        if (request.operation != KSWORD_ARK_HVM_NOATTACH_OPEN && request.operation <= KSWORD_ARK_HVM_NOATTACH_CLOSE && argc != 1)
            return false;
        if ((request.operation == KSWORD_ARK_HVM_NOATTACH_STEP || request.operation == KSWORD_ARK_HVM_NOATTACH_CONTINUE ||
             request.operation >= KSWORD_ARK_HVM_NOATTACH_ADD_BREAKPOINT) && !stop)
        { api.log("No current stop; run ksna_query after the pending request reaches a real user-thread stop"); return false; }
        return send(request);
    }
}

extern "C" __declspec(dllexport) bool pluginit(PluginInit* init)
{
    const auto debug = GetModuleHandleW(L"x64dbg.dll");
    const auto bridge = GetModuleHandleW(L"x64bridge.dll");
    if (!init || !resolve(debug, "_plugin_registercommand", api.registerCommand) ||
        !resolve(debug, "_plugin_unregistercommand", api.unregisterCommand) ||
        !resolve(debug, "_plugin_logputs", api.log) || !resolve(bridge, "DbgIsDebugging", api.debugging)) return false;
    init->sdkVersion = 1; init->pluginVersion = 1; pluginHandle = init->pluginHandle;
    strcpy_s(init->pluginName, "KSword independent no-attach control");
    std::size_t registered = 0;
    for (const char* name : commands)
    {
        if (!api.registerCommand(pluginHandle, name, command, false))
        { for (std::size_t i = 0; i < registered; ++i) api.unregisterCommand(pluginHandle, commands[i]); return false; }
        ++registered;
    }
    api.log("KSword no-attach commands ready. Start with ksna_open PID, TID, confirm [, nested]. Native F7/F9 are separate.");
    return true;
}

extern "C" __declspec(dllexport) bool plugstop()
{
    std::lock_guard<std::recursive_mutex> lock(mutex);
    if (session || uncertainOwner)
    {
        KSWORD_ARK_HVM_NOATTACH_REQUEST query{};
        if (!send(query)) return false;
        if (session || uncertainOwner)
        { query.operation = KSWORD_ARK_HVM_NOATTACH_CLOSE; if (!send(query) || session || uncertainOwner) return false; }
    }
    for (const char* name : commands) api.unregisterCommand(pluginHandle, name);
    backendCall = nullptr;
    if (backendModule) FreeLibrary(backendModule);
    backendModule = nullptr;
    return true;
}
