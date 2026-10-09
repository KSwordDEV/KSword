#pragma once
#include "../Common.h"
#include "../../../driver/KswordArkKeyboardIoctl.h"
#include <commctrl.h>
#include <shlobj.h>
#include <shobjidl.h>
#include <tlhelp32.h>
#include <cstdint>
#include <optional>
#include <unordered_set>
#include <vector>
namespace ks::r3::process_detail::hotkeys {
constexpr std::uint16_t kAcceleratorEndFlag = 0x0080U;
struct HotkeyCandidate final {
    std::wstring objectText;
    std::wstring hotkeyText;
    std::wstring processName;
    std::wstring sourceText;
    std::wstring detailText;
    DWORD processId = 0;
    DWORD threadId = 0;
    std::uint32_t hotkeyId = 0;
    std::uint32_t modifiers = 0;
    std::uint32_t virtualKey = 0;
    bool hasR0Snapshot = false;
    KSWORD_ARK_KEYBOARD_HOTKEY_ENTRY r0Snapshot{};
};
struct AcceleratorResourceEntry final {
    std::uint16_t flags = 0;
    std::uint16_t key = 0;
    std::uint16_t commandId = 0;
    std::uint16_t padding = 0;
};
struct WindowContext final {
    DWORD processId = 0;
    std::unordered_set<HWND> seen;
    std::vector<HWND> windows;
};
struct AcceleratorContext final {
    HMODULE module = nullptr;
    DWORD processId = 0;
    const std::wstring* processName = nullptr;
    std::vector<HotkeyCandidate>* rows = nullptr;
    std::unordered_set<std::wstring>* dedupe = nullptr;
};
std::wstring HexText(std::uint64_t value);
void AppendDiagnostic(std::wstring& target, const std::wstring& text);
std::uint32_t ModifiersFromHotkeyf(std::uint32_t value);
std::wstring VirtualKeyText(std::uint32_t virtualKey);
std::wstring FormatHotkey(std::uint32_t modifiers, std::uint32_t virtualKey);
void AddCandidate(
    std::vector<HotkeyCandidate>& rows,
    std::unordered_set<std::wstring>& dedupe,
    HotkeyCandidate candidate);
void AddWindow(WindowContext& context, HWND window);
BOOL CALLBACK CollectTopLevelWindow(HWND window, LPARAM value);
BOOL CALLBACK CollectThreadWindow(HWND window, LPARAM value);
std::vector<HWND> CollectProcessWindows(DWORD processId);
std::wstring WindowTitle(HWND window);
std::optional<wchar_t> MenuMnemonic(const std::wstring& text);
void CollectMenuHotkeysRecursive(
    HMENU menu,
    HWND window,
    DWORD processId,
    const std::wstring& processName,
    std::vector<HotkeyCandidate>& rows,
    std::unordered_set<std::wstring>& dedupe);
void CollectWindowAndMenuHotkeys(
    DWORD processId,
    const std::wstring& processName,
    std::vector<HotkeyCandidate>& rows,
    std::unordered_set<std::wstring>& dedupe);
std::wstring ResourceNameText(LPWSTR name);
BOOL CALLBACK EnumerateAcceleratorResource(HMODULE, LPCWSTR, LPWSTR resourceName, LONG_PTR value);
void CollectAcceleratorHotkeys(
    DWORD processId,
    const std::wstring& processName,
    const std::wstring& imagePath,
    std::vector<HotkeyCandidate>& rows,
    std::unordered_set<std::wstring>& dedupe,
    std::wstring& diagnostic);
bool EqualPath(const std::wstring& left, const std::wstring& right);
std::vector<std::wstring> ShortcutRoots();
void CollectShortcutHotkeys(
    DWORD processId,
    const std::wstring& processName,
    const std::wstring& imagePath,
    std::vector<HotkeyCandidate>& rows,
    std::unordered_set<std::wstring>& dedupe,
    std::wstring& diagnostic);
static_assert(sizeof(AcceleratorResourceEntry) == 8U);
}
