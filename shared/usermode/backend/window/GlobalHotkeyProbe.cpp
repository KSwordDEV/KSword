#include "GlobalHotkeyProbe.h"
#include <algorithm>
#include <array>
#include <cwchar>
#include <sstream>
#include <chrono>
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
HotkeyProbeResult ProbeHotkeys(const HotkeyProbeOptions& options) {
    HotkeyProbeResult result;
    result.threadId = ::GetCurrentThreadId();
    const std::vector<ProbeKey> keys = options.keys.empty() ? BuildProbeKeys() : options.keys;
    const UINT modifierMaskCount = 1u << (sizeof(kModifiers) / sizeof(kModifiers[0]));
    const auto count = options.modifiers.empty() ? modifierMaskCount - 1 : options.modifiers.size();
    result.requested = count * keys.size();result.entries.reserve((std::min)(result.requested,options.maxEntries));
    const auto started = std::chrono::steady_clock::now();

    for (UINT mask = 1; mask <= count; ++mask) {
        UINT modifiers = 0;
        for (std::size_t bit = 0; bit < sizeof(kModifiers) / sizeof(kModifiers[0]); ++bit) {
            if ((mask & (1u << bit)) != 0) {
                modifiers |= kModifiers[bit].value;
            }
        }
        if (!options.modifiers.empty()) modifiers = options.modifiers[mask-1];
        const std::wstring modifierText = ModifierText(modifiers);

        for (const ProbeKey& key : keys) {
            if (options.cancelled && options.cancelled()) {result.cancelled = true;return result;}
            if (result.entries.size()>=options.maxEntries || std::chrono::steady_clock::now()-started>std::chrono::seconds(8)) {result.limited = true;return result;}
            HotkeyProbeEntry entry;
            entry.modifiers = modifiers;
            entry.virtualKey = key.virtualKey;
            entry.modifierText = modifierText;
            entry.keyText = key.name;
            entry.combination = modifierText + L"+" + entry.keyText;

            entry.reservedF12 = key.virtualKey == VK_F12;
            if (entry.reservedF12 && options.skipReservedF12) {result.entries.push_back(std::move(entry));continue;}
            entry.attempted = true;::SetLastError(ERROR_SUCCESS);
            if (::RegisterHotKey(nullptr, kProbeHotkeyId, modifiers, key.virtualKey)) {
                entry.registered = true;entry.unregisterAttempted = true;::SetLastError(ERROR_SUCCESS);
                entry.unregistered = ::UnregisterHotKey(nullptr, kProbeHotkeyId) != FALSE;
                if (!entry.unregistered) {entry.unregisterError = ::GetLastError();result.cleanupFailed = true;}
                entry.available = true;
                ++result.available;
            } else {
                entry.error = ::GetLastError();
                if (entry.error != ERROR_HOTKEY_ALREADY_REGISTERED) ++result.unknown;
                ++result.occupied;
            }
            result.entries.push_back(std::move(entry));
            if (result.cleanupFailed) return result; // Never reuse an ID whose registration was not released.
        }
    }
    result.complete = result.entries.size() == result.requested;
    return result;
}
}
