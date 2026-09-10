#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <cstdint>

// No C++ translation unit takes these function addresses. The fixture exposes
// them as data symbols from another translation unit, reproducing direct-only
// helpers that are absent from a CFG-enabled image's GFIDS table.
extern "C" __declspec(noinline) void* DwmPrivateFind(void* list, HWND window)
{ return window == reinterpret_cast<HWND>(0x7788) ? list : nullptr; }

extern "C" __declspec(noinline) LIST_ENTRY* DwmPrivateDesktop(void* list, std::uint64_t desktop)
{ return desktop == 0x1234567887654321ULL ? static_cast<LIST_ENTRY*>(list) : nullptr; }
