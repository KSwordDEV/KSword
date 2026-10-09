#pragma once
#include "../Common.h"
#include "WindowQueries.h"
#include <shellapi.h>
namespace ks::r3::window_tools {
constexpr std::size_t kPreviewCharLimit = 64 * 1024;
struct PredefinedFormat final {
    UINT format;
    const wchar_t* name;
};
constexpr PredefinedFormat kPredefinedFormats[] = {
    { CF_TEXT,            L"CF_TEXT" },
    { CF_BITMAP,          L"CF_BITMAP" },
    { CF_METAFILEPICT,    L"CF_METAFILEPICT" },
    { CF_SYLK,            L"CF_SYLK" },
    { CF_DIF,             L"CF_DIF" },
    { CF_TIFF,            L"CF_TIFF" },
    { CF_OEMTEXT,         L"CF_OEMTEXT" },
    { CF_DIB,             L"CF_DIB" },
    { CF_PALETTE,         L"CF_PALETTE" },
    { CF_PENDATA,         L"CF_PENDATA" },
    { CF_RIFF,            L"CF_RIFF" },
    { CF_WAVE,            L"CF_WAVE" },
    { CF_UNICODETEXT,     L"CF_UNICODETEXT" },
    { CF_ENHMETAFILE,     L"CF_ENHMETAFILE" },
    { CF_HDROP,           L"CF_HDROP" },
    { CF_LOCALE,          L"CF_LOCALE" },
    { CF_DIBV5,           L"CF_DIBV5" },
    { CF_OWNERDISPLAY,    L"CF_OWNERDISPLAY" },
    { CF_DSPTEXT,         L"CF_DSPTEXT" },
    { CF_DSPBITMAP,       L"CF_DSPBITMAP" },
    { CF_DSPMETAFILEPICT, L"CF_DSPMETAFILEPICT" },
    { CF_DSPENHMETAFILE,  L"CF_DSPENHMETAFILE" },
};
struct ClipboardFormatInfo final {
    UINT format = 0;
    std::wstring name;
    std::wstring category;
    std::wstring sizeText;
    std::wstring note;
    std::wstring preview;
};
struct ClipboardSnapshot final {
    bool opened = false;
    DWORD openError = 0;
    DWORD sequenceNumber = 0;
    int formatCount = 0;
    HWND owner = nullptr;
    HWND openerWindow = nullptr;
    HWND viewerWindow = nullptr;
    DWORD ownerProcessId = 0;
    std::wstring ownerTitle;
    std::wstring ownerClass;
    std::wstring ownerProcess;
    std::vector<ClipboardFormatInfo> formats;
};
class ScopedClipboard final {
public:
    explicit ScopedClipboard(HWND owner) {
        constexpr int kAttempts = 4;
        for (int attempt = 0; attempt < kAttempts; ++attempt) {
            if (::OpenClipboard(owner)) {
                opened_ = true;
                return;
            }
            lastError_ = ::GetLastError();
            if (attempt + 1 < kAttempts) {
                ::Sleep(12);
            }
        }
    }

    ~ScopedClipboard() {
        if (opened_) {
            ::CloseClipboard();
        }
    }

    ScopedClipboard(const ScopedClipboard&) = delete;
    ScopedClipboard& operator=(const ScopedClipboard&) = delete;

    bool opened() const noexcept { return opened_; }
    DWORD lastError() const noexcept { return lastError_; }

private:
    bool opened_ = false;
    DWORD lastError_ = 0;
};
std::wstring PredefinedFormatName(const UINT format);
std::wstring FormatCategory(const UINT format);
bool IsHandleBackedFormat(const UINT format);
std::wstring ResolveFormatName(const UINT format);
std::wstring ByteSizeText(const SIZE_T bytes);
std::wstring ReadUnicodePreview(bool& truncated);
std::wstring ReadAnsiPreview(bool& truncated);
ClipboardSnapshot CaptureClipboardSnapshot(HWND owner);
}
