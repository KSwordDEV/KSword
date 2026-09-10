#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include "OrderPlan.h"
#include "RuntimeResolver.h"
#include "NativeQueries.h"
#include "../shared/window/DwmProcessIdentity.h"

namespace ks::dwm_order
{
    namespace
    {
        using ZOrderFn = HRESULT (__fastcall*)(void*, void*, void*);
        using UpdateFn = HRESULT (__fastcall*)(void*);
        using DestroyFn = HRESULT (__fastcall*)(void*, void*);
        unsigned char* g_udwm = nullptr;
        runtime::Resolved g_runtime{};
        CRITICAL_SECTION* g_dwmLock = nullptr;
        SRWLOCK g_setupLock = SRWLOCK_INIT;
        const NativeQueries* g_queries = nullptr;
        ZOrderFn g_zOrder = nullptr;
        UpdateFn g_updateScene = nullptr;
        DestroyFn g_destroyWindow = nullptr;
        thread_local unsigned g_nativeDepth = 0;

        // All state and scratch storage below are protected by DWM's own lock.
        struct State
        {
            bool installed = false;
            bool active = false;
            Request request;
            void* targetData = nullptr;
            void* referenceData = nullptr;
            void* targetDwmWindow = nullptr;
            void* referenceDwmWindow = nullptr;
            Status lastStatus = Status::Ok;
        } g_state;
        struct Snapshot
        {
            LIST_ENTRY* head = nullptr;
            std::size_t count = 0;
            std::uintptr_t nodes[8192]{};
        } g_snapshot;

        template<class T> T Read(const void* object, std::uintptr_t offset)
        {
            T value{};
            std::memcpy(&value, static_cast<const unsigned char*>(object) + offset, sizeof(value));
            return value;
        }

        bool Readable(const void* pointer, std::size_t bytes)
        {
            auto address = reinterpret_cast<std::uintptr_t>(pointer);
            if (!address || bytes > UINTPTR_MAX - address) return false;
            const auto end = address + bytes;
            while (address < end)
            {
                MEMORY_BASIC_INFORMATION info{};
                if (!VirtualQuery(reinterpret_cast<void*>(address), &info, sizeof(info))
                    || info.State != MEM_COMMIT || (info.Protect & (PAGE_GUARD | PAGE_NOACCESS)))
                    return false;
                const auto next = reinterpret_cast<std::uintptr_t>(info.BaseAddress) + info.RegionSize;
                if (next <= address) return false;
                address = next;
            }
            return true;
        }

        bool ResolveImage(unsigned char* image, runtime::Resolved& resolved)
        {
            if (!Readable(image, sizeof(IMAGE_DOS_HEADER))) return false;
            const auto dos = Read<IMAGE_DOS_HEADER>(image, 0);
            if (dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew < 0 || dos.e_lfanew > 0x1000)
                return false;
            if (!Readable(image + dos.e_lfanew, sizeof(IMAGE_NT_HEADERS64))) return false;
            const auto nt = Read<IMAGE_NT_HEADERS64>(image, dos.e_lfanew);
            return runtime::Resolve(image, nt.OptionalHeader.SizeOfImage,
                reinterpret_cast<std::uintptr_t>(image), resolved) == runtime::Failure::None;
        }

        Status Initialize()
        {
            Status result = Status::UnsupportedRuntime;
            AcquireSRWLockExclusive(&g_setupLock);
            __try
            {
                if (g_udwm) return Status::Ok;
                wchar_t path[MAX_PATH]{};
                const DWORD length = GetModuleFileNameW(nullptr, path, MAX_PATH);
                if (!length || length >= MAX_PATH) return result;
                const wchar_t* name = wcsrchr(path, L'\\');
                if (!name || _wcsicmp(name + 1, L"dwm.exe")) return result;
                auto* image = reinterpret_cast<unsigned char*>(GetModuleHandleW(L"udwm.dll"));
                runtime::Resolved resolved{};
                if (!ResolveImage(image, resolved)) return result;
                auto* lock = reinterpret_cast<CRITICAL_SECTION*>(image + resolved.criticalSection);
                if (!Readable(lock, sizeof(*lock))) return result;
                const auto* queries = NativeQueries::Create(
                    reinterpret_cast<NativeQueries::FindWindowFn>(image + resolved.functions[static_cast<unsigned>(runtime::Node::FindWindow)]),
                    reinterpret_cast<NativeQueries::DesktopListFn>(image + resolved.functions[static_cast<unsigned>(runtime::Node::DesktopList)]));
                if (!queries) return Status::NativeFailure;
                g_queries = queries;
                g_zOrder = reinterpret_cast<ZOrderFn>(image + resolved.functions[static_cast<unsigned>(runtime::Node::ZOrder)]);
                g_updateScene = reinterpret_cast<UpdateFn>(image + resolved.functions[static_cast<unsigned>(runtime::Node::UpdateScene)]);
                g_destroyWindow = reinterpret_cast<DestroyFn>(image + resolved.functions[static_cast<unsigned>(runtime::Node::DestroyWindow)]);
                g_dwmLock = lock;
                g_runtime = resolved;
                g_udwm = image;
                result = Status::Ok;
            }
            __finally { ReleaseSRWLockExclusive(&g_setupLock); }
            return result;
        }

        void* WindowList()
        {
            auto* manager = Read<void*>(g_udwm, g_runtime.desktopManager);
            if (!Readable(manager, g_runtime.windowListOffset + sizeof(void*))) return nullptr;
            auto* list = Read<void*>(manager, g_runtime.windowListOffset);
            if (!Readable(list, sizeof(void*))
                || Read<void*>(list, 0) != g_udwm + g_runtime.vtable) return nullptr;
            return list;
        }

        bool SameWindow(const WindowIdentity& identity, bool checkCreation, std::uint64_t process = 0)
        {
            HWND hwnd = reinterpret_cast<HWND>(identity.hwnd);
            DWORD pid = 0;
            const DWORD tid = GetWindowThreadProcessId(hwnd, &pid);
            if (!identity.hwnd || !tid || tid != identity.threadId || pid != identity.processId
                || GetAncestor(hwnd, GA_ROOT) != hwnd) return false;
            if (!checkCreation) return true;
            return MatchesProcessIdentity(reinterpret_cast<HANDLE>(process), identity);
        }

        void* Find(void* list, std::uint64_t hwnd)
        {
            auto* data = g_queries->FindWindow(list, reinterpret_cast<HWND>(hwnd));
            if (!Readable(data, g_runtime.layout.dataVisual + sizeof(void*))
                || Read<std::uint64_t>(data, g_runtime.layout.dataHwnd) != hwnd
                || !Read<void*>(data, g_runtime.layout.dataDwmWindow)) return nullptr;
            return data;
        }

        bool Capture(void* list, void* target)
        {
            g_snapshot.count = 0;
            g_snapshot.head = g_queries->DesktopList(list, Read<std::uint64_t>(target, g_runtime.layout.dataDesktop));
            auto* head = g_snapshot.head;
            if (!Readable(head, sizeof(*head))) return false;
            auto* previous = head;
            auto* node = head->Flink;
            bool found = false;
            while (node != head)
            {
                if (g_snapshot.count == 8192 || !Readable(node, g_runtime.layout.dataVisual + sizeof(void*))
                    || node->Blink != previous
                    || Read<std::uint64_t>(node, g_runtime.layout.dataDesktop)
                        != Read<std::uint64_t>(target, g_runtime.layout.dataDesktop)) return false;
                g_snapshot.nodes[g_snapshot.count++] = reinterpret_cast<std::uintptr_t>(node);
                found = found || node == target;
                previous = node;
                node = node->Flink;
            }
            return found && head->Blink == previous;
        }

        HRESULT NativeOrder(void* list, void* target, void* behind)
        {
            HRESULT result = E_FAIL;
            ++g_nativeDepth;
            __try
            {
                result = g_zOrder(list, Read<void*>(target, g_runtime.layout.dataDwmWindow),
                    behind ? Read<void*>(behind, g_runtime.layout.dataDwmWindow) : nullptr);
            }
            __finally { --g_nativeDepth; }
            return result;
        }

        HRESULT NativeUpdate(void* list)
        {
            HRESULT result = E_FAIL;
            ++g_nativeDepth;
            __try { result = g_updateScene(list); }
            __finally { --g_nativeDepth; }
            return result;
        }

        Status Move(void* list, void* target, void* reference, Position position, HRESULT& hr)
        {
            if (reference && Read<std::uint64_t>(reference, g_runtime.layout.dataDesktop)
                != Read<std::uint64_t>(target, g_runtime.layout.dataDesktop)) return Status::DifferentDesktop;
            if (!Read<void*>(target, g_runtime.layout.dataVisual)) return Status::WindowNotComposed;
            if (!Capture(list, target)) return Status::VerificationFailed;
            const auto plan = PlanOrder(g_snapshot.nodes, g_snapshot.count,
                reinterpret_cast<std::uintptr_t>(target), position,
                reinterpret_cast<std::uintptr_t>(reference));
            if (!plan.valid) return Status::InvalidWindow;
            auto* expected = plan.behind
                ? reinterpret_cast<LIST_ENTRY*>(plan.behind) : g_snapshot.head;
            if (!plan.unchanged)
            {
                hr = NativeOrder(list, target, reinterpret_cast<void*>(plan.behind));
                if (FAILED(hr)) return Status::NativeFailure;
            }
            return Capture(list, target) && static_cast<LIST_ENTRY*>(target)->Blink == expected
                ? Status::Ok : Status::VerificationFailed;
        }

        Status RestoreSystemOrder(void* list, const WindowIdentity& identity, HRESULT& hr)
        {
            if (!SameWindow(identity, false)) return Status::InvalidWindow;
            auto* target = Find(list, identity.hwnd);
            if (!target) return Status::WindowNotComposed;
            if (!Capture(list, target)) return Status::VerificationFailed;
            void* behind = nullptr;
            // Win32 walks top-to-bottom with NEXT, opposite to the native Flink
            // list. The native insertion anchor must be below the restored HWND.
            HWND candidate = GetWindow(reinterpret_cast<HWND>(identity.hwnd), GW_HWNDNEXT);
            unsigned visited = 0;
            while (candidate && visited++ < 8192)
            {
                auto* data = Find(list, reinterpret_cast<std::uint64_t>(candidate));
                if (data && data != target
                    && Read<std::uint64_t>(data, g_runtime.layout.dataDesktop)
                        == Read<std::uint64_t>(target, g_runtime.layout.dataDesktop))
                {
                    for (std::size_t i = 0; i < g_snapshot.count; ++i)
                        if (g_snapshot.nodes[i] == reinterpret_cast<std::uintptr_t>(data)) behind = data;
                    if (behind) break;
                }
                candidate = GetWindow(candidate, GW_HWNDNEXT);
            }
            if (candidate && !behind) return Status::VerificationFailed;
            auto* expected = behind ? static_cast<LIST_ENTRY*>(behind) : g_snapshot.head;
            if (static_cast<LIST_ENTRY*>(target)->Blink != expected)
            {
                hr = NativeOrder(list, target, behind);
                if (FAILED(hr)) return Status::NativeFailure;
            }
            return Capture(list, target) && static_cast<LIST_ENTRY*>(target)->Blink == expected
                ? Status::Ok : Status::VerificationFailed;
        }

        void Maintain(void* list)
        {
            if (!g_state.active || g_nativeDepth) return;
            auto* target = Find(list, g_state.request.target.hwnd);
            void* reference = nullptr;
            const bool relative = g_state.request.position == Position::Before
                || g_state.request.position == Position::After;
            if (relative) reference = Find(list, g_state.request.reference.hwnd);
            if (target != g_state.targetData || !SameWindow(g_state.request.target, false)
                || (relative && (reference != g_state.referenceData
                    || !SameWindow(g_state.request.reference, false))))
            {
                g_state.active = false;
                g_state.lastStatus = Status::InvalidWindow;
                // A reference disappearing releases the surviving target.
                if (target == g_state.targetData && target)
                {
                    HRESULT hr = S_OK;
                    RestoreSystemOrder(list, g_state.request.target, hr);
                }
                return;
            }
            HRESULT hr = S_OK;
            g_state.lastStatus = Move(list, target, reference, g_state.request.position, hr);
            if (g_state.lastStatus != Status::Ok) g_state.active = false;
        }

        HRESULT __fastcall UpdateHook(void* list)
        {
            HRESULT hr = E_FAIL;
            EnterCriticalSection(g_dwmLock);
            __try
            {
                __try { if (list == WindowList()) Maintain(list); }
                __except (EXCEPTION_EXECUTE_HANDLER)
                { g_state.active = false; g_state.lastStatus = Status::InternalException; }
                ++g_nativeDepth;
                __try { hr = g_updateScene(list); }
                __finally { --g_nativeDepth; }
            }
            __finally { LeaveCriticalSection(g_dwmLock); }
            return hr;
        }

        HRESULT __fastcall ZOrderHook(void* list, void* target, void* behind)
        {
            HRESULT hr = E_FAIL;
            EnterCriticalSection(g_dwmLock);
            __try
            {
                ++g_nativeDepth;
                __try { hr = g_zOrder(list, target, behind); }
                __finally { --g_nativeDepth; }
                __try { if (SUCCEEDED(hr) && list == WindowList()) Maintain(list); }
                __except (EXCEPTION_EXECUTE_HANDLER)
                { g_state.active = false; g_state.lastStatus = Status::InternalException; }
            }
            __finally { LeaveCriticalSection(g_dwmLock); }
            return hr;
        }

        HRESULT __fastcall DestroyHook(void* list, void* window)
        {
            HRESULT hr = E_FAIL;
            EnterCriticalSection(g_dwmLock);
            __try
            {
                if (g_state.active && (window == g_state.targetDwmWindow || window == g_state.referenceDwmWindow))
                {
                    const bool referenceDestroyed = window != g_state.targetDwmWindow;
                    g_state.active = false;
                    g_state.lastStatus = Status::InvalidWindow;
                    if (referenceDestroyed)
                    {
                        __try { RestoreSystemOrder(list, g_state.request.target, hr); }
                        __except (EXCEPTION_EXECUTE_HANDLER) { g_state.lastStatus = Status::InternalException; }
                    }
                }
                ++g_nativeDepth;
                __try { hr = g_destroyWindow(list, window); }
                __finally { --g_nativeDepth; }
            }
            __finally { LeaveCriticalSection(g_dwmLock); }
            return hr;
        }

        Status SetHooks(bool install)
        {
            if (g_state.installed == install) return Status::Ok;
            auto** table = reinterpret_cast<void**>(g_udwm + g_runtime.vtable);
            const std::size_t slots[] = {g_runtime.destroySlot, g_runtime.zOrderSlot, g_runtime.updateSlot};
            void* originals[] = {reinterpret_cast<void*>(g_destroyWindow), reinterpret_cast<void*>(g_zOrder), reinterpret_cast<void*>(g_updateScene)};
            void* hooks[] = {reinterpret_cast<void*>(&DestroyHook), reinterpret_cast<void*>(&ZOrderHook), reinterpret_cast<void*>(&UpdateHook)};
            for (unsigned i = 0; i < 3; ++i)
                if (table[slots[i]] != (install ? originals[i] : hooks[i])) return Status::HookConflict;
            if (install)
            {
                HMODULE pinned = nullptr;
                if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
                    reinterpret_cast<LPCWSTR>(&UpdateHook), &pinned)) return Status::NativeFailure;
            }
            DWORD protection = 0;
            const std::size_t bytes = (std::max)({g_runtime.destroySlot, g_runtime.zOrderSlot, g_runtime.updateSlot}) * sizeof(void*) + sizeof(void*);
            if (!VirtualProtect(table, bytes, PAGE_READWRITE, &protection)) return Status::NativeFailure;
            bool ok = true;
            unsigned changed = 0;
            for (; changed < 3; ++changed)
            {
                void* expected = install ? originals[changed] : hooks[changed];
                void* desired = install ? hooks[changed] : originals[changed];
                if (InterlockedCompareExchangePointer(table + slots[changed], desired, expected) != expected)
                { ok = false; break; }
            }
            if (!ok)
                while (changed)
                {
                    --changed;
                    InterlockedCompareExchangePointer(table + slots[changed],
                        install ? originals[changed] : hooks[changed], install ? hooks[changed] : originals[changed]);
                }
            DWORD ignored = 0;
            const BOOL protectedAgain = VirtualProtect(table, bytes, protection, &ignored);
            if (ok) g_state.installed = install;
            return ok && protectedAgain ? Status::Ok : Status::HookConflict;
        }

        void Describe(void* list, const Request& request, Response& response)
        {
            response.dwmProcessId = GetCurrentProcessId();
            response.flags |= g_state.installed ? HooksInstalled : 0;
            response.flags |= g_state.active ? Maintaining : 0;
            response.maintainedWindow = g_state.active ? g_state.request.target.hwnd : 0;
            response.maintenanceStatus = g_state.lastStatus;
            auto* target = Find(list, request.target.hwnd);
            if (!target || !Capture(list, target)) return;
            const auto location = LocateOrder(g_snapshot.nodes, g_snapshot.count, reinterpret_cast<std::uintptr_t>(target));
            if (!location.valid) return;
            response.windowCount = static_cast<std::uint32_t>(g_snapshot.count);
            response.band = Read<DWORD>(target, g_runtime.layout.dataBand);
            response.index = location.fromFront;
            response.previous = location.above ? Read<std::uint64_t>(reinterpret_cast<void*>(location.above), g_runtime.layout.dataHwnd) : 0;
            response.next = location.below ? Read<std::uint64_t>(reinterpret_cast<void*>(location.below), g_runtime.layout.dataHwnd) : 0;
        }

        void ExecuteLocked(Packet& packet)
        {
            auto& response = packet.response;
            const auto& request = packet.request;
            void* list = WindowList();
            if (!list) { response.status = Status::UnsupportedRuntime; return; }
            if (request.action == Action::Stop)
            {
                HRESULT restoreHr = S_OK;
                response.status = Status::Ok;
                if (g_state.active)
                {
                    g_state.active = false;
                    response.status = RestoreSystemOrder(list, g_state.request.target, restoreHr);
                    if (response.status == Status::InvalidWindow || response.status == Status::WindowNotComposed)
                        response.status = Status::Ok;
                }
                const auto hookStatus = SetHooks(false);
                if (response.status == Status::Ok) response.status = hookStatus;
                if (response.status == Status::Ok)
                {
                    restoreHr = NativeUpdate(list);
                    if (FAILED(restoreHr)) response.status = Status::NativeFailure;
                    else { response.flags |= Verified | Restored; g_state.lastStatus = Status::Ok; }
                }
                response.nativeResult = restoreHr;
                Describe(list, request, response);
                return;
            }
            if (!SameWindow(request.target, true, packet.targetProcess)) { response.status = Status::InvalidWindow; return; }
            auto* target = Find(list, request.target.hwnd);
            if (!target) { response.status = Status::WindowNotComposed; return; }
            HRESULT hr = S_OK;
            if (request.action == Action::Query)
                response.status = Capture(list, target) ? Status::Ok : Status::VerificationFailed;
            else if (request.action == Action::Restore)
            {
                if (g_state.active && request.target.hwnd == g_state.request.target.hwnd)
                {
                    g_state.active = false;
                }
                response.status = RestoreSystemOrder(list, request.target, hr);
                if (response.status == Status::Ok) response.flags |= Restored;
                if (!g_state.active)
                {
                    const auto hookStatus = SetHooks(false);
                    if (response.status == Status::Ok) response.status = hookStatus;
                }
            }
            else if (request.action == Action::Apply)
            {
                void* reference = nullptr;
                if (request.position == Position::Before || request.position == Position::After)
                {
                    if (!SameWindow(request.reference, true, packet.referenceProcess) || request.reference.hwnd == request.target.hwnd)
                    { response.status = Status::InvalidWindow; goto finished; }
                    reference = Find(list, request.reference.hwnd);
                    if (!reference) { response.status = Status::WindowNotComposed; goto finished; }
                    if (Read<std::uint64_t>(target, g_runtime.layout.dataDesktop) != Read<std::uint64_t>(reference, g_runtime.layout.dataDesktop))
                    { response.status = Status::DifferentDesktop; goto finished; }
                }
                if (g_state.active)
                {
                    g_state.active = false;
                    response.status = RestoreSystemOrder(list, g_state.request.target, hr);
                    if (response.status != Status::Ok) goto finished;
                }
                response.status = request.maintain ? SetHooks(true) : SetHooks(false);
                if (response.status != Status::Ok) goto finished;
                response.status = Move(list, target, reference, request.position, hr);
                g_state.lastStatus = response.status;
                if (response.status == Status::Ok && request.maintain)
                {
                    g_state.request = request;
                    g_state.targetData = target;
                    g_state.referenceData = reference;
                    g_state.targetDwmWindow = Read<void*>(target, g_runtime.layout.dataDwmWindow);
                    g_state.referenceDwmWindow = reference ? Read<void*>(reference, g_runtime.layout.dataDwmWindow) : nullptr;
                    g_state.active = true;
                }
            }
        finished:
            if (request.action != Action::Query && response.status == Status::Ok)
            {
                // This native entry respects DWM's animation-thread/commit checks.
                const HRESULT committed = NativeUpdate(list);
                if (FAILED(committed)) { hr = committed; response.status = Status::NativeFailure; }
            }
            response.nativeResult = hr;
            if (response.status == Status::Ok)
            {
                response.flags |= Verified;
                if (request.action == Action::Restore && !g_state.active) g_state.lastStatus = Status::Ok;
            }
            Describe(list, request, response);
        }

        void Execute(Packet& packet)
        {
            packet.response = {};
            if (packet.magic != kMagic || packet.version != kProtocolVersion || packet.bytes != sizeof(Packet)
                || packet.reserved || packet.request.reserved || packet.request.maintain > 1
                || packet.request.action > Action::Stop || packet.request.position > Position::After)
            { packet.response.status = Status::InvalidRequest; return; }
            packet.response.status = Initialize();
            if (packet.response.status != Status::Ok) return;
            const ULONGLONG deadline = GetTickCount64() + 2000;
            while (!TryEnterCriticalSection(g_dwmLock))
            {
                if (GetTickCount64() >= deadline)
                { packet.response.status = Status::Timeout; return; }
                Sleep(1);
            }
            __try { ExecuteLocked(packet); }
            __finally { LeaveCriticalSection(g_dwmLock); }
        }
    }
}

extern "C" __declspec(dllexport) DWORD WINAPI KswordDwmZOrderRequest(void* parameter)
{
    using namespace ks::dwm_order;
    if (!parameter) return ERROR_INVALID_PARAMETER;
    __try
    {
        Execute(*static_cast<Packet*>(parameter));
        return ERROR_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        // Never turn an access fault into a successful ordering receipt.
        return ERROR_UNHANDLED_EXCEPTION;
    }
}

BOOL WINAPI DllMain(HMODULE, DWORD, void*)
{
    // Initialization starts in the exported request, outside the loader lock.
    // Keep thread notifications for the statically linked CRT and thread_local state.
    return TRUE;
}
