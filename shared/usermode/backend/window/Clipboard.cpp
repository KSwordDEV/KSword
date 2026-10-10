#include "Clipboard.h"
#include <algorithm>
#include <cwchar>
#include <cstring>
#include <sstream>
#include <chrono>
#include <set>
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
std::wstring ResolveFormatName(const UINT format,bool* known,DWORD* error) {
    if (known) *known = false;if (error) *error = ERROR_SUCCESS;
    const std::wstring predefined = PredefinedFormatName(format);
    if (!predefined.empty()) {
        if (known) *known = true;return predefined;
    }
    if (format<0xC000) return L"(无名称)";
    wchar_t buffer[256]{};::SetLastError(ERROR_SUCCESS);
    const int copied = ::GetClipboardFormatNameW(format, buffer, static_cast<int>(sizeof(buffer) / sizeof(buffer[0])));
    if (copied > 0) {
        if (known) *known = true;return std::wstring(buffer, buffer + copied);
    }
    if (error) *error = ::GetLastError();return L"(无名称)";
}
std::wstring ByteSizeText(const SIZE_T bytes) {
    std::wstring text = std::to_wstring(static_cast<std::uint64_t>(bytes)) + L" 字节";
    if (bytes >= 1024) {
        text += L"（约 " + std::to_wstring(static_cast<std::uint64_t>(bytes / 1024)) + L" KB）";
    }
    return text;
}
namespace {
class MemoryLock final {
public:
    MemoryLock(HANDLE handle,ClipboardTextEvidence& evidence):handle_(handle),evidence_(evidence) {
        ::SetLastError(ERROR_SUCCESS);data_ = ::GlobalLock(handle_);if (!data_) evidence_.error = ::GetLastError();
    }
    ~MemoryLock() {close();}
    void close() {
        if (!data_) return;data_ = nullptr;evidence_.unlockAttempted = true;::SetLastError(ERROR_SUCCESS);
        const auto remaining = ::GlobalUnlock(handle_);const auto error = remaining ? ERROR_SUCCESS : ::GetLastError();
        evidence_.unlockError = error;evidence_.unlocked = error == ERROR_SUCCESS;
    }
    const void* get() const {return data_;}
private:
    HANDLE handle_;ClipboardTextEvidence& evidence_;void* data_ = nullptr;
};
HANDLE ReadData(UINT format,DWORD& error) {
    ::SetLastError(ERROR_SUCCESS);const auto handle = ::GetClipboardData(format);error = handle ? ERROR_SUCCESS : ::GetLastError();return handle;
}
bool MemorySize(HANDLE handle,SIZE_T& size,DWORD& error) {
    ::SetLastError(ERROR_SUCCESS);size = ::GlobalSize(handle);error = size ? ERROR_SUCCESS : ::GetLastError();return size != 0 || error == ERROR_SUCCESS;
}
std::wstring Preview(HANDLE handle,UINT format,ClipboardTextEvidence& e,std::size_t requested) {
    const auto limit = (std::min)(requested,kPreviewCharLimit);e.attempted = true;
    if (!handle) return {};
    e.sizeKnown = MemorySize(handle,e.byteSize,e.error);if (!e.sizeKnown) return {};
    const bool unicode = format == CF_UNICODETEXT;
    if (!e.byteSize || (unicode && e.byteSize%sizeof(wchar_t))) {e.malformed = true;e.error = ERROR_INVALID_DATA;return {};}
    MemoryLock lock(handle,e);if (!lock.get()) return {};
    const std::size_t units = unicode ? e.byteSize/sizeof(wchar_t) : e.byteSize;
    const auto scan = (std::min)(units,limit+1);std::size_t length = 0;
    const auto* wide = static_cast<const wchar_t*>(lock.get());const auto* narrow = static_cast<const char*>(lock.get());
    while (length<scan && (unicode ? wide[length] != L'\0' : narrow[length] != '\0')) ++length;
    e.terminationKnown = length<scan || scan==units;e.terminated = length<scan;
    if (e.terminationKnown && !e.terminated) {e.malformed = true;e.error = ERROR_INVALID_DATA;}
    e.truncated = length>limit;if (e.truncated) length = limit;
    if (unicode && length && length<units && wide[length-1]>=0xD800 && wide[length-1]<=0xDBFF && wide[length]>=0xDC00 && wide[length]<=0xDFFF) {--length;e.truncated = true;}
    std::wstring text;
    if (unicode) {
        text.assign(wide,wide+length);
        for (std::size_t i = 0;i<length;++i) {
            if (wide[i]>=0xD800 && wide[i]<=0xDBFF) {if (i+1<length && wide[i+1]>=0xDC00 && wide[i+1]<=0xDFFF) ++i;else {e.malformed = true;e.error = ERROR_INVALID_DATA;}}
            else if (wide[i]>=0xDC00 && wide[i]<=0xDFFF) {e.malformed = true;e.error = ERROR_INVALID_DATA;}
        }
    } else {
        e.codePage = ::GetACP();
        if (length) {
            const int required = ::MultiByteToWideChar(CP_ACP,0,narrow,static_cast<int>(length),nullptr,0);
            if (required<=0) {e.error = ::GetLastError();return {};}
            text.resize(static_cast<std::size_t>(required));
            if (::MultiByteToWideChar(CP_ACP,0,narrow,static_cast<int>(length),text.data(),required)!=required) {e.error = ::GetLastError();return {};}
        }
    }
    e.available = !e.malformed;lock.close();return text;
}
void DescribeOwner(ClipboardSnapshot& snapshot) {
    snapshot.ownerTitle = WindowTitleText(snapshot.owner);snapshot.ownerClass = WindowClassText(snapshot.owner);
    snapshot.ownerProcess = ProcessNameFromId(snapshot.ownerProcessId);
}
}
std::wstring ReadUnicodePreview(bool& truncated,ClipboardTextEvidence* output,std::size_t limit) {
    ClipboardTextEvidence local;auto& e = output ? *output : local;e = {};const auto handle = ReadData(CF_UNICODETEXT,e.error);
    const auto text = Preview(handle,CF_UNICODETEXT,e,limit);truncated = e.truncated;return text;
}
std::wstring ReadAnsiPreview(bool& truncated,ClipboardTextEvidence* output,std::size_t limit) {
    ClipboardTextEvidence local;auto& e = output ? *output : local;e = {};const auto handle = ReadData(CF_TEXT,e.error);
    const auto text = Preview(handle,CF_TEXT,e,limit);truncated = e.truncated;return text;
}
ClipboardSnapshot CaptureClipboardSnapshot(HWND owner,const ClipboardCaptureOptions& options) {
    ClipboardSnapshot snapshot;snapshot.sequenceNumber = ::GetClipboardSequenceNumber();snapshot.owner = ::GetClipboardOwner();
    snapshot.openerWindow = ::GetOpenClipboardWindow();snapshot.viewerWindow = ::GetClipboardViewer();
    ::SetLastError(ERROR_SUCCESS);snapshot.formatCount = ::CountClipboardFormats();snapshot.countError = snapshot.formatCount ? ERROR_SUCCESS : ::GetLastError();snapshot.countKnown = snapshot.formatCount>=0 && !snapshot.countError;
    if (snapshot.owner) {snapshot.ownerThreadId = ::GetWindowThreadProcessId(snapshot.owner,&snapshot.ownerProcessId);if (!snapshot.ownerThreadId) snapshot.ownerError = ::GetLastError();if (options.ownerDescriptions) DescribeOwner(snapshot);}
    ScopedClipboard clipboard(owner);
    if (!clipboard.opened()) {snapshot.openError = clipboard.lastError();return snapshot;}
    snapshot.opened = true;snapshot.sequenceNumber = ::GetClipboardSequenceNumber();snapshot.owner = ::GetClipboardOwner();snapshot.ownerProcessId = 0;
    snapshot.ownerThreadId = 0;snapshot.ownerError = ERROR_SUCCESS;
    if (snapshot.owner) {snapshot.ownerThreadId = ::GetWindowThreadProcessId(snapshot.owner,&snapshot.ownerProcessId);if (!snapshot.ownerThreadId) snapshot.ownerError = ::GetLastError();if (options.ownerDescriptions) DescribeOwner(snapshot);}
    ::SetLastError(ERROR_SUCCESS);snapshot.formatCount = ::CountClipboardFormats();snapshot.countError = snapshot.formatCount ? ERROR_SUCCESS : ::GetLastError();snapshot.countKnown = snapshot.formatCount>=0 && !snapshot.countError;
    const bool targeted = options.autoText || options.textFormat != 0;
    snapshot.textFormat = options.autoText ? (::IsClipboardFormatAvailable(CF_UNICODETEXT) ? CF_UNICODETEXT : ::IsClipboardFormatAvailable(CF_TEXT) ? CF_TEXT : 0) : options.textFormat;
    snapshot.textFormatAvailable = snapshot.textFormat && ::IsClipboardFormatAvailable(snapshot.textFormat);
    UINT previous = 0;std::set<UINT> seen;const auto started = std::chrono::steady_clock::now();
    for (std::size_t ordinal = 0;ordinal<65536;++ordinal) {
        if (std::chrono::steady_clock::now()-started>std::chrono::seconds(8)) {snapshot.limited = true;break;}
        ::SetLastError(ERROR_SUCCESS);const UINT format = ::EnumClipboardFormats(previous);
        if (!format) {snapshot.enumError = ::GetLastError();snapshot.enumComplete = snapshot.enumError == ERROR_SUCCESS;break;}
        if (format>0xFFFF || !seen.insert(format).second) {snapshot.enumError = ERROR_INVALID_DATA;break;}previous = format;
        ClipboardFormatInfo info;info.format = format;info.name = ResolveFormatName(format,&info.nameKnown,&info.nameError);info.category = FormatCategory(format);
        const bool preview = options.previews && !targeted && (format == CF_UNICODETEXT || format == CF_TEXT);
        HANDLE handle = nullptr;
        if (IsHandleBackedFormat(format)) {info.sizeText = L"—";info.note = L"GDI / 显示句柄，非内存对象，无法用 GlobalSize 度量";}
        else if (options.materialize || preview) {
            info.dataRequested = true;handle = ReadData(format,info.dataError);info.dataAvailable = handle != nullptr;
            if (handle) {info.sizeKnown = MemorySize(handle,info.byteSize,info.sizeError);info.sizeText = ByteSizeText(info.byteSize);}
            else {info.sizeText = L"—";info.note = L"GetClipboardData 返回空，通常是延迟渲染失败或所有者已退出";}
        }
        if (preview) {
            ClipboardTextEvidence e;e.error = info.dataError;info.preview = Preview(handle,format,e,options.previewUnits);
            if (e.truncated) info.preview += L"\r\n\r\n[预览已截断，仅显示前 " + std::to_wstring(options.previewUnits) + L" 个字符]";
            if (info.note.empty()) info.note = L"可在下方预览文本内容";
        }
        if (info.note.empty()) info.note = L"二进制内容，本页不做解码";
        snapshot.formats.push_back(std::move(info));
    }
    if (!snapshot.enumComplete && !snapshot.enumError) snapshot.limited = true;
    if (targeted && options.previews && snapshot.textFormatAvailable) {
        const auto handle = ReadData(snapshot.textFormat,snapshot.textEvidence.error);
        snapshot.text = Preview(handle,snapshot.textFormat,snapshot.textEvidence,options.previewUnits);
    }
    snapshot.sequenceAfter = ::GetClipboardSequenceNumber();snapshot.changed = snapshot.sequenceAfter != snapshot.sequenceNumber;
    snapshot.closed = clipboard.close();snapshot.closeAttempted = clipboard.closeAttempted();snapshot.closeError = clipboard.closeError();return snapshot;
}
}
