#pragma once
#include <Windows.h>
#include <cstdint>
#include <cstring>
#include "../../APIMonitor_x64/hook/CodePageAllocator.h"

namespace apimon
{
    // cdecl dispatchers return EDX:EAX. Caller cleanup is explicit and never guessed.
    inline void* BuildX86FakeStub(void* context, void* dispatcher, unsigned stackBytes) noexcept
    {
        if (stackBytes > 65532 || (stackBytes & 3)) return nullptr;
        auto* code = detail::AllocateCodePage();
        if (!code) return nullptr;
        unsigned cursor = 0;
        auto byte = [&](unsigned b) { code[cursor++] = static_cast<unsigned char>(b); };
        auto word = [&](std::uintptr_t value) { std::memcpy(code + cursor, &value, 4); cursor += 4; };
        byte(0xF3); byte(0x0F); byte(0x1E); byte(0xFB);
        byte(0x55); byte(0x8B); byte(0xEC);
        byte(0x68); word(reinterpret_cast<std::uintptr_t>(context));
        byte(0xB8); word(reinterpret_cast<std::uintptr_t>(dispatcher));
        byte(0xFF); byte(0xD0); byte(0x83); byte(0xC4); byte(4);
        byte(0x8B); byte(0xE5); byte(0x5D);
        byte(0xC2); byte(stackBytes & 255); byte(stackBytes >> 8);
        DWORD previous = 0;
        if (!VirtualProtect(code, 4096, PAGE_EXECUTE_READ, &previous))
        { detail::ReleaseCodePage(code); return nullptr; }
        FlushInstructionCache(GetCurrentProcess(), code, cursor); return code;
    }
    // Save flags, integer registers, x87/MMX/XMM, then tail-call the stable original slot.
    inline void* BuildX86RawStub(void* context, void* dispatcher, void** original) noexcept
    {
        auto* code = detail::AllocateCodePage();
        if (!code) return nullptr;
        unsigned cursor = 0;
        auto byte = [&](unsigned b) { code[cursor++] = static_cast<unsigned char>(b); };
        auto word = [&](std::uintptr_t value) { std::memcpy(code + cursor, &value, 4); cursor += 4; };
        byte(0xF3); byte(0x0F); byte(0x1E); byte(0xFB);
        byte(0x9C); byte(0x60); byte(0x8B); byte(0xEC);
        byte(0x81); byte(0xEC); word(528); byte(0x83); byte(0xE4); byte(0xF0);
        byte(0x0F); byte(0xAE); byte(0x04); byte(0x24); // aligned fxsave
        byte(0xFC); // clear DF before C++, restore saved flags afterwards
        byte(0x68); word(reinterpret_cast<std::uintptr_t>(context));
        byte(0xB8); word(reinterpret_cast<std::uintptr_t>(dispatcher)); byte(0xFF); byte(0xD0);
        byte(0x83); byte(0xC4); byte(4);
        byte(0x0F); byte(0xAE); byte(0x0C); byte(0x24);
        byte(0x8B); byte(0xE5); byte(0x61); byte(0x9D);
        byte(0xFF); byte(0x25); word(reinterpret_cast<std::uintptr_t>(original));
        DWORD previous = 0;
        if (!VirtualProtect(code, 4096, PAGE_EXECUTE_READ, &previous))
        { detail::ReleaseCodePage(code); return nullptr; }
        FlushInstructionCache(GetCurrentProcess(), code, cursor); return code;
    }
}
