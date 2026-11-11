#pragma once
#include <Windows.h>
#include <cstdint>
#include <cstddef>

namespace apimon
{
    // These are untyped ABI locations, not a guessed signature/argument count.
    // Saved register frames are owned by our stub. Stack reads never follow an
    // argument pointer and stay within this thread's committed stack bounds.
    struct RawAbiSnapshot
    {
        // Return address present at API entry (normally the instruction after
        // CALL); a thunk or tail jump may make its origin less direct.
        std::uintptr_t returnAddress = 0;
        std::uintptr_t registers[4]{};
        std::uintptr_t stack[4]{};
        unsigned stackCount = 0;
    };
    inline void ReadRawStackSlots(const std::uintptr_t* slots, RawAbiSnapshot& result) noexcept
    {
        const auto* tib = reinterpret_cast<const NT_TIB*>(NtCurrentTeb());
        const auto low = reinterpret_cast<std::uintptr_t>(tib->StackLimit);
        const auto high = reinterpret_cast<std::uintptr_t>(tib->StackBase);
        auto address = reinterpret_cast<std::uintptr_t>(slots);
        __try {
            for (unsigned i = 0; i < 4 && address >= low && address < high && high - address >= sizeof(std::uintptr_t); ++i)
            {
                result.stack[result.stackCount++] = *reinterpret_cast<const std::uintptr_t*>(address);
                address += sizeof(std::uintptr_t);
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {}
    }
    inline std::uintptr_t ReadRawReturnAddress(const std::uintptr_t* slot) noexcept
    {
        const auto* tib = reinterpret_cast<const NT_TIB*>(NtCurrentTeb());
        const auto low = reinterpret_cast<std::uintptr_t>(tib->StackLimit);
        const auto high = reinterpret_cast<std::uintptr_t>(tib->StackBase);
        const auto address = reinterpret_cast<std::uintptr_t>(slot);
        if (address < low || address >= high || high - address < sizeof(std::uintptr_t)) return 0;
        __try { return *slot; }
        __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
    }
    inline RawAbiSnapshot CaptureRawAbi(const std::uintptr_t* saved) noexcept
    {
        RawAbiSnapshot result;
        if (!saved) return result;
#ifdef _M_IX86
        // pushfd; pushad: EDI,ESI,EBP,savedESP,EBX,EDX,ECX,EAX,flags,return.
        result.returnAddress = ReadRawReturnAddress(saved + 9);
        result.registers[0] = saved[6]; result.registers[1] = saved[5];
        ReadRawStackSlots(saved + 10, result);
#else
        // R11,R10,R9,R8,RDX,RCX,RAX,return, four shadow slots, stack arguments.
        result.returnAddress = ReadRawReturnAddress(saved + 7);
        result.registers[0] = saved[5]; result.registers[1] = saved[4];
        result.registers[2] = saved[3]; result.registers[3] = saved[2];
        ReadRawStackSlots(saved + 12, result);
#endif
        return result;
    }
}
