#include "Clipboard.h"
#include <algorithm>
#include <cwchar>
#include <cstring>
#include <sstream>
#pragma comment(lib,"Shell32.lib")
namespace ks::r3::window_tools {
std::wstring PredefinedFormatName(const UINT format) {
    for (const PredefinedFormat& entry : kPredefinedFormats) {
        if (entry.format == format) {
            return entry.name;
        }
    }
    return {};
}
std::wstring FormatCategory(const UINT format) {
    if (format >= CF_PRIVATEFIRST && format <= CF_PRIVATELAST) {
        return L"私有格式";
    }
    if (format >= CF_GDIOBJFIRST && format <= CF_GDIOBJLAST) {
        return L"GDI 对象";
    }
    if (format >= 0xC000) {
        return L"注册格式";
    }
    return L"预定义";
}
bool IsHandleBackedFormat(const UINT format) {
    switch (format) {
    case CF_BITMAP:
    case CF_DSPBITMAP:
    case CF_PALETTE:
    case CF_ENHMETAFILE:
    case CF_DSPENHMETAFILE:
    case CF_OWNERDISPLAY:
        return true;
    default:
        return format >= CF_GDIOBJFIRST && format <= CF_GDIOBJLAST;
    }
}
std::wstring ResolveFormatName(const UINT format) {
    const std::wstring predefined = PredefinedFormatName(format);
    if (!predefined.empty()) {
        return predefined;
    }
    wchar_t buffer[256]{};
    const int copied = ::GetClipboardFormatNameW(format, buffer, static_cast<int>(sizeof(buffer) / sizeof(buffer[0])));
    if (copied > 0) {
        return std::wstring(buffer, buffer + copied);
    }
    return L"(无名称)";
}
std::wstring ByteSizeText(const SIZE_T bytes) {
    std::wstring text = std::to_wstring(static_cast<std::uint64_t>(bytes)) + L" 字节";
    if (bytes >= 1024) {
        text += L"（约 " + std::to_wstring(static_cast<std::uint64_t>(bytes / 1024)) + L" KB）";
    }
    return text;
}
std::wstring ReadUnicodePreview(bool& truncated) {
    truncated = false;
    HANDLE handle = ::GetClipboardData(CF_UNICODETEXT);
    if (!handle) {
        return {};
    }
    const auto* source = static_cast<const wchar_t*>(::GlobalLock(handle));
    if (!source) {
        return {};
    }
    const SIZE_T bytes = ::GlobalSize(handle);
    const std::size_t maxChars = bytes / sizeof(wchar_t);
    std::size_t length = 0;
    while (length < maxChars && source[length] != L'\0') {
        ++length;
    }
    if (length > kPreviewCharLimit) {
        length = kPreviewCharLimit;
        truncated = true;
    }
    std::wstring text(source, source + length);
    ::GlobalUnlock(handle);
    return text;
}
std::wstring ReadAnsiPreview(bool& truncated) {
    truncated = false;
    HANDLE handle = ::GetClipboardData(CF_TEXT);
    if (!handle) {
        return {};
    }
    const auto* source = static_cast<const char*>(::GlobalLock(handle));
    if (!source) {
        return {};
    }
    const SIZE_T bytes = ::GlobalSize(handle);
    std::size_t length = 0;
    while (length < bytes && source[length] != '\0') {
        ++length;
    }
    if (length > kPreviewCharLimit) {
        length = kPreviewCharLimit;
        truncated = true;
    }
    std::wstring text;
    if (length > 0) {
        const int required = ::MultiByteToWideChar(CP_ACP, 0, source, static_cast<int>(length), nullptr, 0);
        if (required > 0) {
            text.resize(static_cast<std::size_t>(required));
            ::MultiByteToWideChar(CP_ACP, 0, source, static_cast<int>(length), text.data(), required);
        }
    }
    ::GlobalUnlock(handle);
    return text;
}
ClipboardSnapshot CaptureClipboardSnapshot(HWND owner) {
    ClipboardSnapshot snapshot;
    snapshot.sequenceNumber = ::GetClipboardSequenceNumber();
    snapshot.owner = ::GetClipboardOwner();
    snapshot.openerWindow = ::GetOpenClipboardWindow();
    snapshot.viewerWindow = ::GetClipboardViewer();
    snapshot.formatCount = ::CountClipboardFormats();
    if (snapshot.owner) {
        snapshot.ownerTitle = WindowTitleText(snapshot.owner);
        snapshot.ownerClass = WindowClassText(snapshot.owner);
        ::GetWindowThreadProcessId(snapshot.owner, &snapshot.ownerProcessId);
        snapshot.ownerProcess = ProcessNameFromId(snapshot.ownerProcessId);
    }

    ScopedClipboard clipboard(owner);
    if (!clipboard.opened()) {
        snapshot.openError = clipboard.lastError();
        return snapshot;
    }
    snapshot.opened = true;

    for (UINT format = ::EnumClipboardFormats(0); format != 0; format = ::EnumClipboardFormats(format)) {
        ClipboardFormatInfo info;
        info.format = format;
        info.name = ResolveFormatName(format);
        info.category = FormatCategory(format);

        if (IsHandleBackedFormat(format)) {
            info.sizeText = L"—";
            info.note = L"GDI / 显示句柄，非内存对象，无法用 GlobalSize 度量";
        } else {
            // GetClipboardData is what forces a delayed-rendered format to be
            // produced: the owner receives WM_RENDERFORMAT and renders it
            // synchronously. That is the price of reporting a real size, and it
            // means a hung clipboard owner can stall this read.
            HANDLE handle = ::GetClipboardData(format);
            if (handle) {
                info.sizeText = ByteSizeText(::GlobalSize(handle));
            } else {
                info.sizeText = L"—";
                info.note = L"GetClipboardData 返回空，通常是延迟渲染失败或所有者已退出";
            }
        }

        if (format == CF_UNICODETEXT || format == CF_TEXT) {
            bool truncated = false;
            info.preview = format == CF_UNICODETEXT ? ReadUnicodePreview(truncated) : ReadAnsiPreview(truncated);
            if (truncated) {
                info.preview += L"\r\n\r\n[预览已截断，仅显示前 " + std::to_wstring(kPreviewCharLimit) + L" 个字符]";
            }
            if (info.note.empty()) {
                info.note = L"可在下方预览文本内容";
            }
        }
        if (info.note.empty()) {
            info.note = L"二进制内容，本页不做解码";
        }
        snapshot.formats.push_back(std::move(info));
    }
    return snapshot;
}
}
