#pragma once
#include "../Common.h"
#include "WindowQueries.h"
namespace ks::r3::window_tools {
constexpr int kProbeHotkeyId = 0x4B57;
struct ModifierChoice final {
    UINT value;
    const wchar_t* name;
};
constexpr ModifierChoice kModifiers[] = {
    { MOD_CONTROL, L"Ctrl" },
    { MOD_ALT,     L"Alt" },
    { MOD_SHIFT,   L"Shift" },
    { MOD_WIN,     L"Win" },
};
struct KeyChoice final {
    UINT virtualKey;
    const wchar_t* name;
};
constexpr KeyChoice kNamedKeys[] = {
    { VK_ESCAPE,     L"Esc" },
    { VK_TAB,        L"Tab" },
    { VK_SPACE,      L"Space" },
    { VK_RETURN,     L"Enter" },
    { VK_BACK,       L"Backspace" },
    { VK_INSERT,     L"Insert" },
    { VK_DELETE,     L"Delete" },
    { VK_HOME,       L"Home" },
    { VK_END,        L"End" },
    { VK_PRIOR,      L"PageUp" },
    { VK_NEXT,       L"PageDown" },
    { VK_LEFT,       L"Left" },
    { VK_UP,         L"Up" },
    { VK_RIGHT,      L"Right" },
    { VK_DOWN,       L"Down" },
    { VK_SNAPSHOT,   L"PrintScreen" },
    { VK_PAUSE,      L"Pause" },
    { VK_OEM_3,      L"`" },
    { VK_OEM_MINUS,  L"-" },
    { VK_OEM_PLUS,   L"=" },
    { VK_OEM_4,      L"[" },
    { VK_OEM_6,      L"]" },
    { VK_OEM_5,      L"\\" },
    { VK_OEM_1,      L";" },
    { VK_OEM_7,      L"'" },
    { VK_OEM_COMMA,  L"," },
    { VK_OEM_PERIOD, L"." },
    { VK_OEM_2,      L"/" },
};
struct HotkeyProbeEntry final {
    UINT modifiers = 0;
    UINT virtualKey = 0;
    std::wstring combination;
    std::wstring modifierText;
    std::wstring keyText;
    bool available = false;
    DWORD error = 0;
};
struct HotkeyProbeResult final {
    std::vector<HotkeyProbeEntry> entries;
    std::size_t occupied = 0;
    std::size_t available = 0;
};
std::wstring ModifierText(const UINT modifiers);
struct ProbeKey final {
    UINT virtualKey = 0;
    std::wstring name;
};
std::vector<ProbeKey> BuildProbeKeys();
HotkeyProbeResult ProbeHotkeys();
}
