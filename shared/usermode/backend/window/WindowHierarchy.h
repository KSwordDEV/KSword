#pragma once
#include "PointerText.h"
#include "../Common.h"
#include "WindowHierarchySupport.h"
#include <dwmapi.h>
#include <shellscalingapi.h>
namespace ks::r3::window_tools {
constexpr int kAncestorChainLimit = 32;
constexpr DWORD kDwmwaExtendedFrameBounds = 9;
constexpr DWORD kDwmwaCloaked = 14;
constexpr DWORD kDwmCloakedApp = 0x00000001;
constexpr DWORD kDwmCloakedShell = 0x00000002;
constexpr DWORD kDwmCloakedInherited = 0x00000004;
struct DpiApi final {
    using GetDpiForWindowFn = UINT(WINAPI*)(HWND);
    using GetWindowDpiAwarenessContextFn = void* (WINAPI*)(HWND);
    using GetAwarenessFromDpiAwarenessContextFn = int(WINAPI*)(void*);
    using GetDpiFromDpiAwarenessContextFn = UINT(WINAPI*)(void*);
    using AreDpiAwarenessContextsEqualFn = BOOL(WINAPI*)(void*, void*);

    GetDpiForWindowFn getDpiForWindow = nullptr;
    GetWindowDpiAwarenessContextFn getWindowContext = nullptr;
    GetAwarenessFromDpiAwarenessContextFn getAwareness = nullptr;
    GetDpiFromDpiAwarenessContextFn getDpiFromContext = nullptr;
    AreDpiAwarenessContextsEqualFn contextsEqual = nullptr;
};
struct DwmApi final {
    using GetWindowAttributeFn = HRESULT(WINAPI*)(HWND, DWORD, PVOID, DWORD);

    GetWindowAttributeFn getWindowAttribute = nullptr;
};
const DpiApi& LoadDpiApi();
const DwmApi& LoadDwmApi();
void* DpiContextSentinel(const std::intptr_t value);
std::wstring DescribeDpiContext(void* context);
void AppendLine(std::wstring& text, const std::wstring& line);
void AppendSection(std::wstring& text, const wchar_t* title);
void AppendField(std::wstring& text, const wchar_t* label, const std::wstring& value);
void AppendBits(std::wstring& text, const std::vector<std::wstring>& bits);
void AppendBasics(std::wstring& text, HWND hwnd);
void AppendAncestry(std::wstring& text, HWND hwnd);
void AppendZOrder(std::wstring& text, HWND hwnd);
void AppendStyles(std::wstring& text, HWND hwnd);
void AppendClassInfo(std::wstring& text, HWND hwnd);
void AppendGeometry(std::wstring& text, HWND hwnd);
void AppendDpi(std::wstring& text, HWND hwnd);
std::wstring CloakStateText(const DWORD flags);
std::wstring HresultText(const HRESULT status);
std::wstring LayeredFlagsText(const DWORD flags);
void AppendCompositionState(std::wstring& text, HWND hwnd);
std::wstring BuildHierarchyReport(HWND hwnd);
enum class HierarchyValueKind {Unsigned,Signed,Boolean,Pointer,Text,Rectangle,Point,Strings};
struct HierarchyField {
    std::wstring name,domain,text;
    HierarchyValueKind kind = HierarchyValueKind::Unsigned;
    bool available = false,notApplicable = false,errorKnown = false;
    std::uint64_t number = 0;
    std::int64_t signedNumber = 0;
    RECT rectangle{};
    POINT point{};
    std::vector<std::wstring> strings;
    DWORD error = 0;
};
struct HierarchySnapshot {
    DWORD chainError = 0,zError = 0;
    bool found = false,stable = false,chainComplete = false,chainCycle = false,chainLimited = false;
    bool zComplete = false,zCycle = false,zLimited = false;
    DWORD processId = 0,threadId = 0,zCount = 0;
    int zIndex = -1;
    std::vector<HWND> parentChain;
    std::vector<HierarchyField> fields;
};
HierarchySnapshot QueryHierarchySnapshot(HWND hwnd);
}
