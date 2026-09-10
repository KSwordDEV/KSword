#pragma once

#include <Windows.h>
#include <cstdint>
#include <new>

namespace ks::dwm_order
{
    // Only the two direct-only uDWM query helpers use these call sites. Bind the
    // exact, validated profile addresses once and seal the table read-only before
    // publishing it. Virtual methods and all other calls retain normal CFG checks.
    class NativeQueries final
    {
    public:
        using FindWindowFn = void* (__fastcall*)(void*, HWND);
        using DesktopListFn = LIST_ENTRY* (__fastcall*)(void*, std::uint64_t);

        static const NativeQueries* Create(FindWindowFn find, DesktopListFn desktop)
        {
            if (!find || !desktop) return nullptr;
            void* storage = VirtualAlloc(nullptr, sizeof(NativeQueries), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
            if (!storage) return nullptr;
            auto* queries = new (storage) NativeQueries(find, desktop);
            DWORD old = 0;
            if (!VirtualProtect(storage, sizeof(NativeQueries), PAGE_READONLY, &old))
            { VirtualFree(storage, 0, MEM_RELEASE); return nullptr; }
            return queries;
        }

        // These helpers are not GFIDS targets in the supported uDWM image. Each
        // non-inlined wrapper makes exactly one call through the sealed binding.
        __declspec(noinline) __declspec(guard(nocf))
        void* FindWindow(void* list, HWND window) const { return find_(list, window); }

        __declspec(noinline) __declspec(guard(nocf))
        LIST_ENTRY* DesktopList(void* list, std::uint64_t desktop) const { return desktop_(list, desktop); }

        static void Destroy(const NativeQueries* queries)
        { if (queries) VirtualFree(const_cast<NativeQueries*>(queries), 0, MEM_RELEASE); }

    private:
        NativeQueries(FindWindowFn find, DesktopListFn desktop) : find_(find), desktop_(desktop) {}
        const FindWindowFn find_;
        const DesktopListFn desktop_;
    };
}
