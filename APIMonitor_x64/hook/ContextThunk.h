#pragma once
#include "CodePageAllocator.h"
#include <Windows.h>
#include <cstdint>
#include <cstring>

namespace apimon
{
    // Integer/pointer x64 ABI only. Insert a stable context before the original arguments.
    // Published code and its unwind table remain valid until process exit.
    inline void* BuildContextThunk(void* context, void* dispatcher, unsigned arguments) noexcept
    {
#ifdef _M_IX86
        // Current completion/extension arguments are 32-bit scalars/pointers, stdcall.
        if (arguments > 11) return nullptr;
        auto* page = detail::AllocateCodePage();
        if (!page) return nullptr;
        unsigned cursor = 0;
        auto byte = [&](unsigned value) { page[cursor++] = static_cast<unsigned char>(value); };
        auto imm32 = [&](std::uintptr_t value) { std::memcpy(page + cursor, &value, 4); cursor += 4; };
        byte(0xF3); byte(0x0F); byte(0x1E); byte(0xFB);
        byte(0x55); byte(0x8B); byte(0xEC);
        for (unsigned index = arguments; index > 0; --index) {
            byte(0xFF); byte(0x75); byte(4 + index * 4);
        }
        byte(0x68); imm32(reinterpret_cast<std::uintptr_t>(context));
        byte(0xB8); imm32(reinterpret_cast<std::uintptr_t>(dispatcher));
        byte(0xFF); byte(0xD0); // stdcall dispatcher removes args including context
        byte(0x8B); byte(0xE5); byte(0x5D);
        byte(0xC2); byte(arguments * 4); byte(0);
        DWORD previous = 0;
        if (!::VirtualProtect(page, 4096, PAGE_EXECUTE_READ, &previous))
        { detail::ReleaseCodePage(page); return nullptr; }
        ::FlushInstructionCache(::GetCurrentProcess(), page, cursor);
        return page;
#else
        if (arguments > 11) return nullptr;
        auto* page = static_cast<unsigned char*>(::VirtualAlloc(nullptr, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
        if (!page) return nullptr;
        unsigned cursor = 0;
        auto byte = [&](unsigned value) { page[cursor++] = static_cast<unsigned char>(value); };
        auto imm64 = [&](std::uintptr_t value) { std::memcpy(page + cursor, &value, 8); cursor += 8; };
        unsigned frame = 32 + (arguments > 3 ? (arguments - 3) * 8 : 0);
        if ((frame & 15) != 8) frame += 8;
        byte(0xF3); byte(0x0F); byte(0x1E); byte(0xFA); // ENDBR64
        byte(0x48); byte(0x83); byte(0xEC); byte(frame);
        // Copy original stack arguments before changing the register arguments.
        for (unsigned argument = 4; argument < arguments; ++argument)
        {
            byte(0x48); byte(0x8B); byte(0x84); byte(0x24);
            const unsigned source = frame + 40 + (argument - 4) * 8;
            std::memcpy(page + cursor, &source, 4); cursor += 4;
            byte(0x48); byte(0x89); byte(0x44); byte(0x24); byte(40 + (argument - 4) * 8);
        }
        if (arguments >= 4) { byte(0x4C); byte(0x89); byte(0x4C); byte(0x24); byte(32); }
        if (arguments >= 3) { byte(0x4D); byte(0x89); byte(0xC1); } // R8 -> R9
        if (arguments >= 2) { byte(0x49); byte(0x89); byte(0xD0); } // RDX -> R8
        if (arguments >= 1) { byte(0x48); byte(0x89); byte(0xCA); } // RCX -> RDX
        byte(0x48); byte(0xB9); imm64(reinterpret_cast<std::uintptr_t>(context));
        byte(0x48); byte(0xB8); imm64(reinterpret_cast<std::uintptr_t>(dispatcher));
        byte(0xFF); byte(0xD0);
        byte(0x48); byte(0x83); byte(0xC4); byte(frame); byte(0xC3);
        auto* function = reinterpret_cast<RUNTIME_FUNCTION*>(page + 288);
        function->BeginAddress = 0; function->EndAddress = cursor; function->UnwindData = 320;
        page[320] = 1; page[321] = 8; page[322] = 1; page[323] = 0;
        page[324] = 8; page[325] = static_cast<unsigned char>(((frame - 8) / 8) << 4 | 2); // UWOP_ALLOC_SMALL
        DWORD previous = 0;
        if (!::VirtualProtect(page, 4096, PAGE_EXECUTE_READ, &previous)
            || !::RtlAddFunctionTable(function, 1, reinterpret_cast<DWORD64>(page)))
        { detail::ReleaseCodePage(page); return nullptr; }
        ::FlushInstructionCache(::GetCurrentProcess(), page, cursor);
        return page;
#endif
    }
}
