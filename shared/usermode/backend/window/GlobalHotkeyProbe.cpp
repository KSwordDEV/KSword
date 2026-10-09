#include "GlobalHotkeyProbe.h"
#include <algorithm>
#include <array>
#include <cwchar>
#include <sstream>
namespace ks::r3::window_tools {
std::wstring ModifierText(const UINT modifiers) {
    std::wstring text;
    for (const ModifierChoice& modifier : kModifiers) {
        if ((modifiers & modifier.value) != 0) {
            if (!text.empty()) {
                text += L"+";
            }
            text += modifier.name;
        }
    }
    return text;
}
std::vector<ProbeKey> BuildProbeKeys() {
    std::vector<ProbeKey> keys;
    keys.reserve(26 + 10 + 24 + sizeof(kNamedKeys) / sizeof(kNamedKeys[0]));
    for (wchar_t letter = L'A'; letter <= L'Z'; ++letter) {
        keys.push_back({ static_cast<UINT>(letter), std::wstring(1, letter) });
    }
    for (wchar_t digit = L'0'; digit <= L'9'; ++digit) {
        keys.push_back({ static_cast<UINT>(digit), std::wstring(1, digit) });
    }
    for (int index = 0; index < 24; ++index) {
        keys.push_back({ static_cast<UINT>(VK_F1 + index), L"F" + std::to_wstring(index + 1) });
    }
    for (const KeyChoice& named : kNamedKeys) {
        keys.push_back({ named.virtualKey, named.name });
    }
    return keys;
}
HotkeyProbeResult ProbeHotkeys() {
    HotkeyProbeResult result;
    const std::vector<ProbeKey> keys = BuildProbeKeys();
    const UINT modifierMaskCount = 1u << (sizeof(kModifiers) / sizeof(kModifiers[0]));
    result.entries.reserve(static_cast<std::size_t>(modifierMaskCount - 1) * keys.size());

    for (UINT mask = 1; mask < modifierMaskCount; ++mask) {
        UINT modifiers = 0;
        for (std::size_t bit = 0; bit < sizeof(kModifiers) / sizeof(kModifiers[0]); ++bit) {
            if ((mask & (1u << bit)) != 0) {
                modifiers |= kModifiers[bit].value;
            }
        }
        const std::wstring modifierText = ModifierText(modifiers);

        for (const ProbeKey& key : keys) {
            HotkeyProbeEntry entry;
            entry.modifiers = modifiers;
            entry.virtualKey = key.virtualKey;
            entry.modifierText = modifierText;
            entry.keyText = key.name;
            entry.combination = modifierText + L"+" + entry.keyText;

            if (::RegisterHotKey(nullptr, kProbeHotkeyId, modifiers, key.virtualKey)) {
                ::UnregisterHotKey(nullptr, kProbeHotkeyId);
                entry.available = true;
                ++result.available;
            } else {
                entry.error = ::GetLastError();
                ++result.occupied;
            }
            result.entries.push_back(std::move(entry));
        }
    }
    return result;
}
}
