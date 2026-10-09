#pragma execution_character_set("utf-8")

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <ShlObj.h>
#include <ShObjIdl.h>
#include <Shellapi.h>
#include <Objbase.h>

#include "KswordGUI/KswordStyle.h"
#include "resource.h"
#include "PayloadResources.h"

#include "Fl.H"
#include "Fl_Window.H"

#include <algorithm>
#include <cstdint>
#include <exception>
#include <fstream>
#include <iomanip>
#include <memory>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "Ole32.lib")

extern HWND fl_win32_xid(const Fl_Window* window);

#ifndef KSWORD_SETUP_ENABLE_TOPMOST
#define KSWORD_SETUP_ENABLE_TOPMOST 0
#endif

namespace {
constexpr int kWindowWidth = 600;
constexpr int kWindowHeight = 504;
constexpr int kLayeredImageWidth = 405;
// kImageOverlap controls how much of the character PNG covers the installer
// panel. 243 is about 60% of the 405px character width; tweak this one value
// when fine-adjusting the horizontal overlap.
constexpr int kImageOverlap = 223;
constexpr int kImageDrawHeight = 720;
constexpr int kImageVerticalOffset = (kImageDrawHeight - kWindowHeight) / 2;
constexpr int kPad = 24;
constexpr wchar_t kDefaultInstallLeaf[] = L"KswordARK";
constexpr wchar_t kStateArg[] = L"--install-state";
constexpr wchar_t kSettingsRel[] = L"Style\\appearance_settings.json";
constexpr wchar_t kMainExe[] = L"Ksword5.1.exe";
constexpr wchar_t kLauncherExe[] = L"Launcher.exe";
constexpr wchar_t kTaskmgrScript[] = L"TaskmgrHijack.ps1";

// AppendPath joins two path fragments without depending on later helpers. Inputs
// are a parent directory and child name; processing inserts one slash when
// needed; output is a Windows path string.
std::wstring AppendPath(const std::wstring& dir, const wchar_t* child) {
    if (dir.empty()) return child ? std::wstring(child) : std::wstring();
    if (!child || !*child) return dir;
    if (dir.back() == L'\\' || dir.back() == L'/') return dir + child;
    return dir + L"\\" + child;
}

// DefaultInstallDir resolves the per-user installation root. Input is none;
// processing prefers %LOCALAPPDATA%\Programs and falls back to %LOCALAPPDATA%;
// output is a writable current-user path that normally does not need UAC.
std::wstring DefaultInstallDir() {
    PWSTR raw = nullptr;
    HRESULT hr = ::SHGetKnownFolderPath(FOLDERID_UserProgramFiles, KF_FLAG_CREATE, nullptr, &raw);
    if (FAILED(hr) || !raw) {
        hr = ::SHGetKnownFolderPath(FOLDERID_LocalAppData, KF_FLAG_CREATE, nullptr, &raw);
    }
    if (SUCCEEDED(hr) && raw) {
        std::wstring dir(raw);
        ::CoTaskMemFree(raw);
        return AppendPath(dir, kDefaultInstallLeaf);
    }

    wchar_t localAppData[MAX_PATH]{};
    DWORD n = ::GetEnvironmentVariableW(L"LOCALAPPDATA", localAppData, MAX_PATH);
    if (n > 0 && n < MAX_PATH) {
        return AppendPath(AppendPath(localAppData, L"Programs"), kDefaultInstallLeaf);
    }
    return AppendPath(L".", kDefaultInstallLeaf);
}

// InstallOptions is the installer input model. Values come from FLTK widgets or
// the elevation handoff JSON file; PerformInstall consumes them and returns no
// mutations through this struct after installation starts.
struct InstallOptions {
    std::wstring installDir = DefaultInstallDir();
    bool startupAdmin = true;
    bool startupMaximized = true;
    bool replaceTaskmgr = false;
    bool testMode = false;
    bool desktopShortcut = true;
    bool startMenuShortcut = true;
    bool launchAfterInstall = true;
};

// InstallResult is the user-visible outcome. Each installation phase appends a
// line to logText, and the final page displays this text in the status control.
struct InstallResult {
    bool ok = true;
    bool rebootNow = false;
    std::wstring logText;
};

// PageLayout groups the right-side safe content rectangle. The left gutter is
// intentionally blank because the character art overlaps that part of the card.
struct PageLayout {
    int cardX = 0;
    int cardY = 0;
    int cardW = 0;
    int cardH = 0;
    int contentX = 0;
    int contentW = 0;
};

KLayeredImageWindow g_characterWindow;
KInput* g_pathInput = nullptr;
KCheckBox* g_adminCheck = nullptr;
KCheckBox* g_maxCheck = nullptr;
KCheckBox* g_taskmgrCheck = nullptr;
KCheckBox* g_testModeCheck = nullptr;
KCheckBox* g_desktopCheck = nullptr;
KCheckBox* g_startMenuCheck = nullptr;
KCheckBox* g_launchCheck = nullptr;
KTextDisplay* g_status = nullptr;
KButton* g_installButton = nullptr;
KButton* g_browseButton = nullptr;
KCard* g_setupPage = nullptr;
KCard* g_installPage = nullptr;
Fl_Window* g_mainWindow = nullptr;
bool g_topMostPaused = false;
std::wstring g_characterImagePath;

// BuildPageLayout computes the reusable installer card geometry. Input is none;
// processing reserves a 30% left gutter for the overlaid character; output is
// the card and safe content rectangle used by every page.
PageLayout BuildPageLayout() {
    PageLayout layout;
    layout.cardX = kPad;
    layout.cardY = 20;
    layout.cardW = kWindowWidth - kPad * 2;
    layout.cardH = kWindowHeight - 40;
    const int gutterW = layout.cardW * 30 / 100;
    layout.contentX = layout.cardX + gutterW + 18;
    layout.contentW = layout.cardW - gutterW - 42;
    return layout;
}

void ApplyInstallerZOrder(Fl_Window* owner);
void SetInstallerShellDialogMode(bool enabled);
int TopMostMessageBox(const wchar_t* text, const wchar_t* caption, UINT type);
void EnsureTaskbarAppWindow(Fl_Window* window);

// WideToUtf8 converts UTF-16 Win32 text to UTF-8 for FLTK widgets. Input is a
// UTF-16 string, processing uses WideCharToMultiByte, and output is UTF-8 bytes.
std::string WideToUtf8(const std::wstring& text) {
    if (text.empty()) return {};
    const int n = ::WideCharToMultiByte(CP_UTF8, 0, text.c_str(), (int)text.size(), nullptr, 0, nullptr, nullptr);
    if (n <= 0) return {};
    std::string out((size_t)n, '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, text.c_str(), (int)text.size(), &out[0], n, nullptr, nullptr);
    return out;
}

// Utf8ToWide converts FLTK UTF-8 text to UTF-16 for Win32 APIs. Input is UTF-8
// bytes, processing uses MultiByteToWideChar, and output is UTF-16 text.
std::wstring Utf8ToWide(const std::string& text) {
    if (text.empty()) return {};
    const int n = ::MultiByteToWideChar(CP_UTF8, 0, text.c_str(), (int)text.size(), nullptr, 0);
    if (n <= 0) return {};
    std::wstring out((size_t)n, L'\0');
    ::MultiByteToWideChar(CP_UTF8, 0, text.c_str(), (int)text.size(), &out[0], n);
    return out;
}

// Trim removes surrounding whitespace from user-entered paths. Input is a string,
// processing scans both ends, and output is the cleaned string.
std::wstring Trim(const std::wstring& text) {
    const wchar_t* ws = L" \t\r\n";
    const size_t first = text.find_first_not_of(ws);
    if (first == std::wstring::npos) return {};
    const size_t last = text.find_last_not_of(ws);
    return text.substr(first, last - first + 1);
}

// Join combines a directory and child path. Inputs are two path fragments,
// processing inserts one separator when needed, and output is a Windows path.
std::wstring Join(const std::wstring& dir, const std::wstring& child) {
    if (dir.empty()) return child;
    if (child.empty()) return dir;
    if (dir.back() == L'\\' || dir.back() == L'/') return dir + child;
    return dir + L"\\" + child;
}

// Parent returns the directory portion of a file path. Input is a path string,
// processing finds the final separator, and output is empty on failure.
std::wstring Parent(const std::wstring& path) {
    const size_t pos = path.find_last_of(L"\\/");
    return pos == std::wstring::npos ? std::wstring() : path.substr(0, pos);
}

// ExistsFile reports whether a non-directory path exists. Input is a candidate
// path, processing queries Win32 attributes, and output is a boolean result.
bool ExistsFile(const std::wstring& path) {
    const DWORD attr = ::GetFileAttributesW(path.c_str());
    return attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

// EnsureDir creates a directory tree. Input is a directory path, processing uses
// SHCreateDirectoryExW for recursive creation, and output is true on success.
bool EnsureDir(const std::wstring& dir) {
    if (dir.empty()) return false;
    const int rc = ::SHCreateDirectoryExW(nullptr, dir.c_str(), nullptr);
    return rc == ERROR_SUCCESS || rc == ERROR_ALREADY_EXISTS || rc == ERROR_FILE_EXISTS;
}

// JsonEscape encodes a wide string as a JSON string body. Input is raw text;
// processing escapes backslash, quote, and control characters; output is JSON-safe.
std::wstring JsonEscape(const std::wstring& text) {
    std::wstring out;
    out.reserve(text.size() + 8);
    for (wchar_t ch : text) {
        switch (ch) {
        case L'\\': out += L"\\\\"; break;
        case L'"': out += L"\\\""; break;
        case L'\b': out += L"\\b"; break;
        case L'\f': out += L"\\f"; break;
        case L'\n': out += L"\\n"; break;
        case L'\r': out += L"\\r"; break;
        case L'\t': out += L"\\t"; break;
        default:
            if (ch < 0x20) {
                wchar_t buf[7]{};
                swprintf_s(buf, L"\\u%04X", (unsigned int)ch);
                out += buf;
            } else {
                out += ch;
            }
            break;
        }
    }
    return out;
}

// JsonUnescape decodes a JSON string body. Input is an escaped UTF-8 token
// without surrounding quotes; processing handles common escape sequences and
// converts the resulting UTF-8 bytes; output is wide text for the state file.
std::wstring JsonUnescape(const std::string& text) {
    std::string out;
    out.reserve(text.size());
    for (size_t i = 0; i < text.size(); ++i) {
        char ch = text[i];
        if (ch != '\\' || i + 1 >= text.size()) {
            out.push_back(ch);
            continue;
        }
        char next = text[++i];
        switch (next) {
        case '\\': out.push_back('\\'); break;
        case '"': out.push_back('"'); break;
        case '/': out.push_back('/'); break;
        case 'b': out.push_back('\b'); break;
        case 'f': out.push_back('\f'); break;
        case 'n': out.push_back('\n'); break;
        case 'r': out.push_back('\r'); break;
        case 't': out.push_back('\t'); break;
        case 'u':
            if (i + 4 < text.size()) {
                unsigned int value = 0;
                for (int k = 0; k < 4; ++k) {
                    char hex = text[i + 1 + (size_t)k];
                    value <<= 4;
                    if (hex >= '0' && hex <= '9') value |= (unsigned int)(hex - '0');
                    else if (hex >= 'A' && hex <= 'F') value |= 10u + (unsigned int)(hex - 'A');
                    else if (hex >= 'a' && hex <= 'f') value |= 10u + (unsigned int)(hex - 'a');
                }
                if (value < 0x80) {
                    out.push_back((char)value);
                } else if (value < 0x800) {
                    out.push_back((char)(0xC0 | (value >> 6)));
                    out.push_back((char)(0x80 | (value & 0x3F)));
                } else {
                    out.push_back((char)(0xE0 | (value >> 12)));
                    out.push_back((char)(0x80 | ((value >> 6) & 0x3F)));
                    out.push_back((char)(0x80 | (value & 0x3F)));
                }
                i += 4;
            }
            break;
        default:
            out.push_back(next);
            break;
        }
    }
    return Utf8ToWide(out);
}

// JsonFindString returns a string value from a small JSON object. Inputs are the
// raw UTF-8 JSON text, the member name, and a default wide string; output is the
// found string or the default when the key is absent.
std::wstring JsonFindString(const std::string& json, const char* key, const std::wstring& defValue) {
    const std::string needle = std::string("\"") + key + "\"";
    size_t keyPos = json.find(needle);
    if (keyPos == std::string::npos) return defValue;
    size_t colon = json.find(':', keyPos + needle.size());
    if (colon == std::string::npos) return defValue;
    size_t start = json.find('"', colon + 1);
    if (start == std::string::npos) return defValue;
    ++start;
    std::string raw;
    raw.reserve(64);
    bool escaped = false;
    for (size_t i = start; i < json.size(); ++i) {
        char ch = json[i];
        if (!escaped && ch == '"') return JsonUnescape(raw);
        if (!escaped && ch == '\\') {
            escaped = true;
            raw.push_back(ch);
            continue;
        }
        escaped = false;
        raw.push_back(ch);
    }
    return defValue;
}

// JsonFindBool returns a boolean member from a small JSON object. Inputs are the
// raw UTF-8 JSON text, the member name, and a default value; output is a parsed
// flag or the default when parsing fails.
bool JsonFindBool(const std::string& json, const char* key, bool defValue) {
    const std::string needle = std::string("\"") + key + "\"";
    size_t keyPos = json.find(needle);
    if (keyPos == std::string::npos) return defValue;
    size_t colon = json.find(':', keyPos + needle.size());
    if (colon == std::string::npos) return defValue;
    size_t start = json.find_first_not_of(" \t\r\n", colon + 1);
    if (start == std::string::npos) return defValue;
    if (json.compare(start, 4, "true") == 0) return true;
    if (json.compare(start, 5, "false") == 0) return false;
    return defValue;
}

// NeedsElevation evaluates whether the requested options touch privileged
// locations. Input is install options; output is true when UAC should be used.
bool NeedsElevation(const InstallOptions& o) {
    return o.replaceTaskmgr || o.testMode;
}

// FileExistsInDir reports whether a file exists under the install root. Input is
// root and relative path; output is a boolean used to detect update installs.
bool FileExistsInDir(const std::wstring& dir, const std::wstring& rel) {
    return ExistsFile(Join(dir, rel));
}

// AppendLog appends one line to the result log and refreshes the status widget.
// Input is mutable log text and one line; processing appends CRLF; no return.
void AppendLog(std::wstring* log, const std::wstring& line) {
    if (!log) return;
    *log += line;
    *log += L"\r\n";
    if (g_status) {
        const std::string utf8 = WideToUtf8(*log);
        g_status->set_text(utf8.c_str());
        Fl::check();
    }
}

// SetStatus replaces status text directly. Input is UTF-16 text; processing
// converts to UTF-8; no value is returned.
void SetStatus(const std::wstring& text) {
    if (!g_status) return;
    const std::string utf8 = WideToUtf8(text);
    g_status->set_text(utf8.c_str());
    Fl::check();
}

// WriteBytes creates or overwrites a file with binary data. Inputs are file path,
// byte pointer and size; processing creates the parent directory; output is true
// when all bytes are written.
bool WriteBytes(const std::wstring& path, const void* data, DWORD size) {
    const std::wstring parent = Parent(path);
    if (!parent.empty() && !EnsureDir(parent)) return false;
    HANDLE h = ::CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    DWORD written = 0;
    const BOOL ok = ::WriteFile(h, data, size, &written, nullptr);
    ::CloseHandle(h);
    return ok && written == size;
}

// ReadBytes loads a file into memory through Win32 wide-path APIs. Input is a
// file path; processing reads the complete stream; output is true on success.
bool ReadBytes(const std::wstring& path, std::vector<char>* data) {
    if (!data) return false;
    data->clear();
    HANDLE h = ::CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER size{};
    if (!::GetFileSizeEx(h, &size) || size.QuadPart < 0 || size.QuadPart > 1024 * 1024) {
        ::CloseHandle(h);
        return false;
    }
    data->resize((size_t)size.QuadPart);
    DWORD read = 0;
    const BOOL ok = data->empty() || ::ReadFile(h, data->data(), (DWORD)data->size(), &read, nullptr);
    ::CloseHandle(h);
    return ok && read == data->size();
}

// ExtractRc writes an embedded RCDATA resource to disk. Inputs are resource id
// and output path; processing locates and locks the resource; output is true when
// extraction succeeds.
bool ExtractRc(unsigned int id, const std::wstring& path) {
    HRSRC res = ::FindResourceW(nullptr, MAKEINTRESOURCEW(id), RT_RCDATA);
    if (!res) return false;
    HGLOBAL loaded = ::LoadResource(nullptr, res);
    const void* bytes = loaded ? ::LockResource(loaded) : nullptr;
    const DWORD size = ::SizeofResource(nullptr, res);
    return bytes && size > 0 && WriteBytes(path, bytes, size);
}

// ExePath returns the current installer executable path. Input is none;
// processing expands a stack buffer through GetModuleFileNameW; output is empty
// on failure.
std::wstring ExePath() {
    std::vector<wchar_t> buf(1024, L'\0');
    while (buf.size() < 32768) {
        DWORD n = ::GetModuleFileNameW(nullptr, buf.data(), (DWORD)buf.size());
        if (n == 0) return {};
        if (n < buf.size()) return {buf.data(), n};
        buf.resize(buf.size() * 2, L'\0');
    }
    return {};
}

// IsElevated checks the current token elevation state. Input is current process;
// processing queries TokenElevation; output is true for administrator elevation.
bool IsElevated() {
    HANDLE token = nullptr;
    if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
    TOKEN_ELEVATION elevation{};
    DWORD len = 0;
    BOOL ok = ::GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &len);
    ::CloseHandle(token);
    return ok && elevation.TokenIsElevated;
}

// Quote returns a quoted command-line argument. Input is raw text, processing
// escapes double quotes, and output is suitable for ShellExecute/CreateProcess.
std::wstring Quote(const std::wstring& arg) {
    std::wstring out = L"\"";
    for (wchar_t ch : arg) out += (ch == L'\"') ? L"\\\"" : std::wstring(1, ch);
    out += L"\"";
    return out;
}

// SystemExePath resolves a system executable inside the Windows directory.
// Input is a relative path under System32; output is an absolute path used to
// avoid CreateProcess search-path ambiguity and WOW64 surprises.
std::wstring SystemExePath(const wchar_t* relativePath) {
    wchar_t sysDir[MAX_PATH]{};
    if (!::GetSystemDirectoryW(sysDir, MAX_PATH)) {
        return relativePath ? std::wstring(relativePath) : std::wstring();
    }
    return Join(sysDir, relativePath ? std::wstring(relativePath) : std::wstring());
}

// TempStatePath allocates an elevation handoff file path. Input is none;
// processing uses GetTempPath/GetTempFileName; output is a temporary path.
std::wstring TempStatePath() {
    wchar_t dir[MAX_PATH]{};
    wchar_t file[MAX_PATH]{};
    if (!::GetTempPathW(MAX_PATH, dir) || !::GetTempFileNameW(dir, L"ksw", 0, file)) return L"KswordSetup.state";
    return file;
}

// SaveState writes install options to a JSON file. Inputs are path and options;
// processing stores UTF-8 state used by the elevated continuation; output is
// true when the handoff file is written.
bool SaveState(const std::wstring& file, const InstallOptions& o) {
    std::wostringstream json;
    json << L"{\n"
         << L"  \"installDir\": \"" << JsonEscape(o.installDir) << L"\",\n"
         << L"  \"startupAdmin\": " << (o.startupAdmin ? L"true" : L"false") << L",\n"
         << L"  \"startupMaximized\": " << (o.startupMaximized ? L"true" : L"false") << L",\n"
         << L"  \"replaceTaskmgr\": " << (o.replaceTaskmgr ? L"true" : L"false") << L",\n"
         << L"  \"testMode\": " << (o.testMode ? L"true" : L"false") << L",\n"
         << L"  \"desktopShortcut\": " << (o.desktopShortcut ? L"true" : L"false") << L",\n"
         << L"  \"startMenuShortcut\": " << (o.startMenuShortcut ? L"true" : L"false") << L",\n"
         << L"  \"launchAfterInstall\": " << (o.launchAfterInstall ? L"true" : L"false") << L"\n"
         << L"}\n";
    const std::string utf8 = WideToUtf8(json.str());
    return WriteBytes(file, utf8.data(), (DWORD)utf8.size());
}

// LoadState reads install options from a JSON handoff file. Input is path;
// processing reads expected fields with defaults; output is reconstructed
// options for the elevated installer instance.
InstallOptions LoadState(const std::wstring& file) {
    InstallOptions o;
    std::vector<char> bytes;
    if (!ReadBytes(file, &bytes)) return o;
    const std::string json(bytes.begin(), bytes.end());
    o.installDir = JsonFindString(json, "installDir", DefaultInstallDir());
    o.startupAdmin = JsonFindBool(json, "startupAdmin", true);
    o.startupMaximized = JsonFindBool(json, "startupMaximized", true);
    o.replaceTaskmgr = JsonFindBool(json, "replaceTaskmgr", false);
    o.testMode = JsonFindBool(json, "testMode", false);
    o.desktopShortcut = JsonFindBool(json, "desktopShortcut", true);
    o.startMenuShortcut = JsonFindBool(json, "startMenuShortcut", true);
    o.launchAfterInstall = JsonFindBool(json, "launchAfterInstall", true);
    return o;
}

// RelaunchElevated starts this installer with runas and an install-state file.
// Input is state path; processing calls ShellExecuteW; output is true if Windows
// accepted the elevated launch request.
bool RelaunchElevated(const std::wstring& stateFile) {
    const std::wstring exe = ExePath();
    if (exe.empty()) return false;
    const std::wstring args = std::wstring(kStateArg) + L" " + Quote(stateFile);
    HINSTANCE rc = ::ShellExecuteW(nullptr, L"runas", exe.c_str(), args.c_str(), Parent(exe).c_str(), SW_SHOWNORMAL);
    return reinterpret_cast<INT_PTR>(rc) > 32;
}

// ShowSetupPage activates the first settings page. Input is none; processing
// flips FLTK group visibility and refreshes the window; no value is returned.
void ShowSetupPage() {
    if (g_setupPage) g_setupPage->show();
    if (g_installPage) g_installPage->hide();
    if (g_mainWindow) g_mainWindow->redraw();
}

// ShowInstallPage activates the second progress/result page. Input is none;
// processing hides the initial settings components and refreshes; no return.
void ShowInstallPage() {
    if (g_setupPage) g_setupPage->hide();
    if (g_installPage) g_installPage->show();
    if (g_mainWindow) g_mainWindow->redraw();
    Fl::check();
}

// CollectOptions reads the current widget state. Input is global FLTK widgets;
// processing applies defaults and trimming; output is an InstallOptions object.
InstallOptions CollectOptions() {
    InstallOptions o;
    if (g_pathInput && g_pathInput->value()) o.installDir = Trim(Utf8ToWide(g_pathInput->value()));
    if (o.installDir.empty()) o.installDir = DefaultInstallDir();
    o.startupAdmin = !g_adminCheck || g_adminCheck->value() != 0;
    o.startupMaximized = !g_maxCheck || g_maxCheck->value() != 0;
    o.replaceTaskmgr = g_taskmgrCheck && g_taskmgrCheck->value() != 0;
    o.testMode = g_testModeCheck && g_testModeCheck->value() != 0;
    o.desktopShortcut = !g_desktopCheck || g_desktopCheck->value() != 0;
    o.startMenuShortcut = !g_startMenuCheck || g_startMenuCheck->value() != 0;
    o.launchAfterInstall = !g_launchCheck || g_launchCheck->value() != 0;
    return o;
}

// ApplyOptions writes saved state back into widgets. Input is install options;
// processing updates each FLTK control; no value is returned.
void ApplyOptions(const InstallOptions& o) {
    if (g_pathInput) g_pathInput->value(WideToUtf8(o.installDir).c_str());
    if (g_adminCheck) g_adminCheck->value(o.startupAdmin ? 1 : 0);
    if (g_maxCheck) g_maxCheck->value(o.startupMaximized ? 1 : 0);
    if (g_taskmgrCheck) g_taskmgrCheck->value(o.replaceTaskmgr ? 1 : 0);
    if (g_testModeCheck) g_testModeCheck->value(o.testMode ? 1 : 0);
    if (g_desktopCheck) g_desktopCheck->value(o.desktopShortcut ? 1 : 0);
    if (g_startMenuCheck) g_startMenuCheck->value(o.startMenuShortcut ? 1 : 0);
    if (g_launchCheck) g_launchCheck->value(o.launchAfterInstall ? 1 : 0);
}

// PayloadDeployment records one switched payload file. The record carries the
// original-file backup needed to restore every earlier replacement on failure.
struct PayloadDeployment {
    std::wstring target;
    std::wstring backup;
    bool replacedExisting = false;
};

// RemovePayloadWorkTree removes only the installer-created staging tree. Input
// is its exact root; processing recursively removes staging files; output is a
// best-effort cleanup result and never touches the installation payload itself.
bool RemovePayloadWorkTree(const std::wstring& root) {
    WIN32_FIND_DATAW findData{};
    HANDLE find = ::FindFirstFileW(Join(root, L"*").c_str(), &findData);
    if (find != INVALID_HANDLE_VALUE) {
        do {
            const std::wstring name(findData.cFileName);
            if (name == L"." || name == L"..") continue;

            const std::wstring child = Join(root, name);
            if ((findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
                RemovePayloadWorkTree(child);
            }
            else {
                ::DeleteFileW(child.c_str());
            }
        } while (::FindNextFileW(find, &findData));
        ::FindClose(find);
    }
    return ::RemoveDirectoryW(root.c_str()) != FALSE || ::GetLastError() == ERROR_FILE_NOT_FOUND;
}

// RestorePayloadDeployments restores already replaced files in reverse order.
// Input is the successful switch list; processing puts backups back in place;
// output is false only when Windows rejects one of the rollback operations.
bool RestorePayloadDeployments(const std::vector<PayloadDeployment>& deployments) {
    bool restored = true;
    for (auto it = deployments.rbegin(); it != deployments.rend(); ++it) {
        if (!it->replacedExisting) {
            if (ExistsFile(it->target) && !::DeleteFileW(it->target.c_str())) {
                restored = false;
            }
            continue;
        }

        if (!ExistsFile(it->backup)) {
            restored = false;
            continue;
        }

        if (ExistsFile(it->target)) {
            if (!::ReplaceFileW(it->target.c_str(), it->backup.c_str(), nullptr,
                REPLACEFILE_WRITE_THROUGH, nullptr, nullptr)) {
                restored = false;
            }
        }
        else if (!::MoveFileExW(it->backup.c_str(), it->target.c_str(), MOVEFILE_WRITE_THROUGH)) {
            restored = false;
        }
    }
    return restored;
}

// SwitchStagedPayloadFile installs one fully written staging file. Input is the
// staged path, final path, and backup path; output describes a reversible switch.
bool SwitchStagedPayloadFile(const std::wstring& staged, const std::wstring& target,
    const std::wstring& backup, PayloadDeployment* deployment) {
    if (!deployment || !EnsureDir(Parent(target))) return false;

    deployment->target = target;
    deployment->backup = backup;
    deployment->replacedExisting = ExistsFile(target);

    if (deployment->replacedExisting) {
        if (!EnsureDir(Parent(backup))) return false;
        return ::ReplaceFileW(target.c_str(), staged.c_str(), backup.c_str(),
            REPLACEFILE_WRITE_THROUGH, nullptr, nullptr) != FALSE;
    }

    return ::MoveFileExW(staged.c_str(), target.c_str(), MOVEFILE_WRITE_THROUGH) != FALSE;
}

// ExtractPayload stages every generated resource before any live file changes.
// Input is install options and log text; processing commits reversible switches;
// output is true only when the full payload becomes available as one update.
bool ExtractPayload(const InstallOptions& o, std::wstring* log) {
    if (!EnsureDir(o.installDir)) {
        AppendLog(log, L"创建安装目录失败: " + o.installDir);
        return false;
    }

    // 使用进程号和时钟构成只属于本次安装的工作目录，避免覆盖已有安装内容。
    const std::wstring workRoot = Join(o.installDir, L".kswordsetup-staging-" +
        std::to_wstring(::GetCurrentProcessId()) + L"-" + std::to_wstring(::GetTickCount64()));
    if (!::CreateDirectoryW(workRoot.c_str(), nullptr)) {
        AppendLog(log, L"创建安装临时目录失败: " + workRoot);
        return false;
    }

    const std::wstring payloadRoot = Join(workRoot, L"payload");
    const std::wstring backupRoot = Join(workRoot, L"backup");
    for (unsigned int i = 0; i < kKswordSetupPayloadResourceCount; ++i) {
        const auto& e = kKswordSetupPayloadResources[i];
        const std::wstring staged = Join(payloadRoot, e.relativePath);
        AppendLog(log, L"准备: " + std::wstring(e.relativePath));
        if (!ExtractRc(e.resourceId, staged)) {
            AppendLog(log, L"准备安装文件失败: " + staged);
            RemovePayloadWorkTree(workRoot);
            return false;
        }
    }

    // 仅当所有资源已完整写入 staging 后才接触现有安装；失败时恢复之前的文件。
    std::vector<PayloadDeployment> deployments;
    deployments.reserve(kKswordSetupPayloadResourceCount);
    for (unsigned int i = 0; i < kKswordSetupPayloadResourceCount; ++i) {
        const auto& e = kKswordSetupPayloadResources[i];
        const std::wstring target = Join(o.installDir, e.relativePath);
        const std::wstring staged = Join(payloadRoot, e.relativePath);
        const std::wstring backup = Join(backupRoot, e.relativePath);
        PayloadDeployment deployment;

        AppendLog(log, L"安装: " + std::wstring(e.relativePath));
        if (!SwitchStagedPayloadFile(staged, target, backup, &deployment)) {
            const DWORD error = ::GetLastError();
            const bool restored = RestorePayloadDeployments(deployments);
            AppendLog(log, L"安装切换失败，错误码: " + std::to_wstring(error) + L"，已" +
                (restored ? L"恢复原有文件。" : L"尝试恢复原有文件，但仍有文件未恢复。"));
            // 回滚不完整时保留工作目录中的备份，避免清理动作抹掉最后一份可恢复原文件。
            if (restored) {
                RemovePayloadWorkTree(workRoot);
            }
            else {
                AppendLog(log, L"已保留恢复备份目录: " + workRoot);
            }
            return false;
        }
        deployments.push_back(std::move(deployment));
    }

    // 成功后备份不再需要；删除仅限本次随机 staging 目录，不影响用户文件或配置。
    RemovePayloadWorkTree(workRoot);
    return true;
}

// WriteSettings creates or optionally overwrites Style/appearance_settings.json.
// Input is install options; processing asks before replacing existing settings;
// output is true when the final policy is applied successfully.
bool WriteSettings(const InstallOptions& o, std::wstring* log) {
    const std::wstring file = Join(o.installDir, kSettingsRel);
    if (ExistsFile(file)) {
        SetInstallerShellDialogMode(true);
        int choice = TopMostMessageBox(
            L"检测到已有配置文件。\n\n选择“是”覆盖安装器生成配置；选择“否”保留原有一切配置。",
            L"KswordSetup 覆盖安装", MB_ICONQUESTION | MB_YESNO | MB_DEFBUTTON2);
        SetInstallerShellDialogMode(false);
        if (choice != IDYES) {
            AppendLog(log, L"保留已有配置: " + file);
            return true;
        }
    }
    std::ostringstream json;
    json << "{\n"
         << "    \"theme_mode\": \"follow_system\",\n"
         << "    \"background_image_path\": \"Style/ksword_background.png\",\n"
         << "    \"background_opacity_percent\": 35,\n"
         << "    \"startup_default_tab_key\": \"welcome\",\n"
         << "    \"startup_maximized\": " << (o.startupMaximized ? "true" : "false") << ",\n"
         << "    \"startup_topmost_enabled\": false,\n"
         << "    \"startup_auto_request_admin\": " << (o.startupAdmin ? "true" : "false") << ",\n"
         << "    \"startup_window_scale_factor\": 1.0,\n"
         << "    \"startup_scale_recommend_prompt_disabled\": false,\n"
         << "    \"unlocker_shell_context_menu_enabled\": false,\n"
         << "    \"slider_wheel_adjust_enabled\": false\n"
         << "}\n";
    const std::string data = json.str();
    if (!WriteBytes(file, data.data(), (DWORD)data.size())) {
        AppendLog(log, L"写入配置失败: " + file);
        return false;
    }
    AppendLog(log, L"写入启动配置: " + file);
    return true;
}

// RunWait starts a process and waits for completion. Inputs are executable,
// arguments, working directory and timeout; processing uses CreateProcessW;
// output is true when exit code is zero.
bool RunWait(const std::wstring& exe, const std::wstring& args, const std::wstring& cwd, DWORD timeoutMs, DWORD* exitCode) {
    std::wstring cmd = Quote(exe) + (args.empty() ? L"" : L" " + args);
    std::vector<wchar_t> mutableCmd(cmd.begin(), cmd.end());
    mutableCmd.push_back(L'\0');
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    if (!::CreateProcessW(exe.c_str(), mutableCmd.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, cwd.empty() ? nullptr : cwd.c_str(), &si, &pi)) {
        if (exitCode) *exitCode = ::GetLastError();
        return false;
    }
    DWORD wait = ::WaitForSingleObject(pi.hProcess, timeoutMs);
    if (wait == WAIT_TIMEOUT) ::TerminateProcess(pi.hProcess, 1460);
    DWORD code = 1;
    ::GetExitCodeProcess(pi.hProcess, &code);
    ::CloseHandle(pi.hThread);
    ::CloseHandle(pi.hProcess);
    if (exitCode) *exitCode = code;
    return wait == WAIT_OBJECT_0 && code == 0;
}

// RunWaitCapture starts a process, waits for completion, and captures combined
// stdout/stderr text for diagnostics. Inputs mirror RunWait plus an output
// buffer; output text is decoded with the OEM code page because console tools
// usually emit that encoding when launched without a console window.
bool RunWaitCapture(const std::wstring& exe, const std::wstring& args, const std::wstring& cwd, DWORD timeoutMs, DWORD* exitCode, std::wstring* output) {
    if (output) output->clear();

    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = nullptr;

    HANDLE readPipe = nullptr;
    HANDLE writePipe = nullptr;
    if (!::CreatePipe(&readPipe, &writePipe, &sa, 0)) {
        if (exitCode) *exitCode = ::GetLastError();
        return false;
    }
    // 读取端绝不能被子进程继承，否则子进程退出后 reader 仍看不到 EOF。
    if (!::SetHandleInformation(readPipe, HANDLE_FLAG_INHERIT, 0)) {
        const DWORD error = ::GetLastError();
        ::CloseHandle(readPipe);
        ::CloseHandle(writePipe);
        if (exitCode) *exitCode = error;
        return false;
    }

    // The launched helper and every descendant are kept in one job.  If a
    // helper exits while a descendant still owns stdout/stderr, closing the job
    // lets the reader finish instead of leaving the installer waiting forever.
    HANDLE job = ::CreateJobObjectW(nullptr, nullptr);
    if (!job) {
        const DWORD error = ::GetLastError();
        ::CloseHandle(readPipe);
        ::CloseHandle(writePipe);
        if (exitCode) *exitCode = error;
        if (output) *output = L"无法创建子进程作业对象。";
        return false;
    }
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION jobInfo{};
    jobInfo.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!::SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            &jobInfo,
            sizeof(jobInfo))) {
        const DWORD error = ::GetLastError();
        ::CloseHandle(job);
        ::CloseHandle(readPipe);
        ::CloseHandle(writePipe);
        if (exitCode) *exitCode = error;
        if (output) *output = L"无法配置子进程作业对象。";
        return false;
    }

    std::wstring cmd = Quote(exe) + (args.empty() ? L"" : L" " + args);
    std::vector<wchar_t> mutableCmd(cmd.begin(), cmd.end());
    mutableCmd.push_back(L'\0');

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = ::GetStdHandle(STD_INPUT_HANDLE);
    si.hStdOutput = writePipe;
    si.hStdError = writePipe;

    PROCESS_INFORMATION pi{};
    const BOOL created = ::CreateProcessW(
        exe.c_str(),
        mutableCmd.data(),
        nullptr,
        nullptr,
        TRUE,
        CREATE_NO_WINDOW | CREATE_SUSPENDED,
        nullptr,
        cwd.empty() ? nullptr : cwd.c_str(),
        &si,
        &pi);
    const DWORD createError = created ? ERROR_SUCCESS : ::GetLastError();

    ::CloseHandle(writePipe);
    writePipe = nullptr;

    if (!created) {
        if (output) {
            *output = L"CreateProcessW failed, last error=" + std::to_wstring(createError);
        }
        ::CloseHandle(readPipe);
        ::CloseHandle(job);
        if (exitCode) *exitCode = createError;
        return false;
    }

    // Assign before resuming so helpers cannot start a child outside our job
    // between CreateProcessW and AssignProcessToJobObject.
    if (!::AssignProcessToJobObject(job, pi.hProcess)) {
        const DWORD error = ::GetLastError();
        ::TerminateProcess(pi.hProcess, error);
        ::WaitForSingleObject(pi.hProcess, 5000);
        ::CloseHandle(readPipe);
        ::CloseHandle(pi.hThread);
        ::CloseHandle(pi.hProcess);
        ::CloseHandle(job);
        if (exitCode) *exitCode = error;
        if (output) *output = L"无法将诊断子进程加入受控作业，last error=" + std::to_wstring(error);
        return false;
    }
    if (::ResumeThread(pi.hThread) == static_cast<DWORD>(-1)) {
        const DWORD error = ::GetLastError();
        ::TerminateJobObject(job, error);
        ::WaitForSingleObject(pi.hProcess, 5000);
        ::CloseHandle(readPipe);
        ::CloseHandle(pi.hThread);
        ::CloseHandle(pi.hProcess);
        ::CloseHandle(job);
        if (exitCode) *exitCode = error;
        if (output) *output = L"无法启动诊断子进程，last error=" + std::to_wstring(error);
        return false;
    }

    // 子进程可能写满匿名管道；同步 drain 可防止父进程等待子进程、子进程等待父进程的死锁。
    std::shared_ptr<std::string> captured;
    std::thread reader;
    try {
        captured = std::make_shared<std::string>();
        reader = std::thread([readPipe, captured]() {
            constexpr size_t kMaxCapturedBytes = 1024 * 1024;
            char buffer[4096];
            DWORD read = 0;
            try {
                while (::ReadFile(readPipe, buffer, sizeof(buffer), &read, nullptr) && read > 0) {
                    // 即使诊断文本超限也继续读空管道，避免重新引入子进程阻塞。
                    const size_t available = captured->size() < kMaxCapturedBytes
                        ? kMaxCapturedBytes - captured->size() : 0;
                    captured->append(buffer, buffer + std::min<size_t>(read, available));
                }
            }
            catch (...) {
                // 诊断缓存失败不应终止安装器；关闭读取端可让子进程收到管道已断开。
            }
            ::CloseHandle(readPipe);
        });
    }
    catch (const std::exception&) {
        // 无法创建 reader 时不能继续运行会写满管道的子进程；有界回收后向 UI 返回错误。
        constexpr DWORD kReaderCreationFailure = ERROR_NOT_ENOUGH_MEMORY;
        ::TerminateJobObject(job, kReaderCreationFailure);
        ::WaitForSingleObject(pi.hProcess, 5000);
        ::CloseHandle(readPipe);
        ::CloseHandle(pi.hThread);
        ::CloseHandle(pi.hProcess);
        ::CloseHandle(job);
        if (exitCode) *exitCode = kReaderCreationFailure;
        if (output) *output = L"无法创建诊断输出读取线程。";
        return false;
    }

    DWORD wait = ::WaitForSingleObject(pi.hProcess, timeoutMs);
    if (wait != WAIT_OBJECT_0) {
        // 超时或等待失败时结束完整进程树，而不是只杀父进程留下持有输出管道的后代。
        ::TerminateJobObject(job, wait == WAIT_TIMEOUT ? 1460 : ::GetLastError());
        ::WaitForSingleObject(pi.hProcess, 5000);
    }

    // PowerShell 或其它工具可能让后代继承输出管道；初始进程退出后仍要有界等待 EOF。
    constexpr DWORD kReaderDrainTimeoutMs = 5000;
    constexpr DWORD kReaderCancelTimeoutMs = 2000;
    const HANDLE readerThread = reinterpret_cast<HANDLE>(reader.native_handle());
    DWORD readerWait = ::WaitForSingleObject(readerThread, kReaderDrainTimeoutMs);
    bool readerCancelled = readerWait != WAIT_OBJECT_0;
    if (readerCancelled) {
        // 先结束作业树，使继承的输出端关闭；这比只终止父进程更可靠。
        ::TerminateJobObject(job, ERROR_OPERATION_ABORTED);
        ::WaitForSingleObject(pi.hProcess, 5000);
        readerWait = ::WaitForSingleObject(readerThread, kReaderDrainTimeoutMs);
    }
    if (readerWait != WAIT_OBJECT_0) {
        // 若 reader 恰好仍阻塞在同步 ReadFile，向目标线程请求取消并只再等待有限时间。
        ::CancelSynchronousIo(readerThread);
        readerWait = ::WaitForSingleObject(readerThread, kReaderCancelTimeoutMs);
    }
    const bool readerDetached = readerWait != WAIT_OBJECT_0;
    if (readerDetached) {
        // 不可安全地强杀未知 I/O 线程；共享缓冲区仍由线程持有，安装器可立即返回。
        reader.detach();
    }
    else {
        reader.join();
    }

    DWORD code = 1;
    ::GetExitCodeProcess(pi.hProcess, &code);
    ::CloseHandle(pi.hThread);
    ::CloseHandle(pi.hProcess);
    ::CloseHandle(job);
    if (exitCode) *exitCode = code;

    if (output && !readerDetached && captured && !captured->empty()) {
        const int wideLen = ::MultiByteToWideChar(CP_OEMCP, 0, captured->data(), (int)captured->size(), nullptr, 0);
        if (wideLen > 0) {
            std::wstring wide((size_t)wideLen, L'\0');
            ::MultiByteToWideChar(CP_OEMCP, 0, captured->data(), (int)captured->size(), &wide[0], wideLen);
            *output = std::move(wide);
        }
    }
    if (output && readerCancelled) {
        *output += L"\r\n诊断输出管道仍被子进程占用，已停止继续等待。";
    }
    if (output && readerDetached) {
        *output += L"\r\n诊断输出读取线程未能及时退出，安装器已放弃等待。";
    }

    return wait == WAIT_OBJECT_0 && code == 0 && !readerCancelled && !readerDetached;
}

// InstallTaskmgr calls the released TaskmgrHijack.ps1 in parameter mode. Input is
// install options; processing points IFEO at installed Ksword5.1.exe; output is
// true when PowerShell exits successfully.
bool InstallTaskmgr(const InstallOptions& o, std::wstring* log) {
    const std::wstring script = Join(o.installDir, kTaskmgrScript);
    const std::wstring target = Join(o.installDir, kMainExe);
    const std::wstring powershell = SystemExePath(L"WindowsPowerShell\\v1.0\\powershell.exe");
    const std::wstring args = L"-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File " + Quote(script) + L" -Install -TargetExe " + Quote(target);
    DWORD code = 1;
    std::wstring detail;
    const bool ok = ExistsFile(script) && ExistsFile(target) && RunWaitCapture(powershell, args, o.installDir, 60000, &code, &detail);
    if (ok) {
        AppendLog(log, L"已替换系统任务管理器。");
    }
    else {
        AppendLog(log, L"任务管理器替换失败，退出码: " + std::to_wstring(code));
        if (!detail.empty()) {
            AppendLog(log, L"详细信息: " + detail);
        }
    }
    return ok;
}

// EnableTestMode runs bcdedit /set testsigning on. Input is log text; processing
// waits for bcdedit; output is true when Windows accepts the setting.
bool EnableTestMode(std::wstring* log) {
    DWORD code = 1;
    const std::wstring bcdedit = SystemExePath(L"bcdedit.exe");
    std::wstring detail;
    const bool ok = RunWaitCapture(bcdedit, L"/set testsigning on", L"", 60000, &code, &detail);
    if (ok) {
        AppendLog(log, L"已执行 bcdedit /set testsigning on。");
    }
    else {
        AppendLog(log, L"启动测试模式失败，退出码: " + std::to_wstring(code));
        if (!detail.empty()) {
            AppendLog(log, L"详细信息: " + detail);
        }
    }
    return ok;
}

// KnownFolder returns a Windows known-folder path. Input is a folder id;
// processing calls SHGetKnownFolderPath; output is empty when unavailable.
std::wstring KnownFolder(const KNOWNFOLDERID& id) {
    PWSTR raw = nullptr;
    HRESULT hr = ::SHGetKnownFolderPath(id, 0, nullptr, &raw);
    if (FAILED(hr) || !raw) return {};
    std::wstring out(raw);
    ::CoTaskMemFree(raw);
    return out;
}

// CreateShortcut writes one .lnk file. Inputs are link path, target and working
// directory; processing uses IShellLinkW/IPersistFile; output is success flag.
bool CreateShortcut(const std::wstring& link, const std::wstring& target, const std::wstring& cwd) {
    if (!EnsureDir(Parent(link))) return false;
    IShellLinkW* sl = nullptr;
    HRESULT hr = ::CoCreateInstance(CLSID_ShellLink, nullptr, CLSCTX_INPROC_SERVER, IID_IShellLinkW, (void**)&sl);
    if (FAILED(hr) || !sl) return false;
    sl->SetPath(target.c_str());
    sl->SetWorkingDirectory(cwd.c_str());
    sl->SetDescription(L"KswordARK");
    IPersistFile* pf = nullptr;
    hr = sl->QueryInterface(IID_IPersistFile, (void**)&pf);
    if (SUCCEEDED(hr) && pf) {
        hr = pf->Save(link.c_str(), TRUE);
        pf->Release();
    }
    sl->Release();
    return SUCCEEDED(hr);
}

// CreateShortcuts creates selected current-user shortcuts. Input is install
// options; processing writes Desktop/Programs links for the interactive user;
// output is true when all requested shortcuts succeed.
bool CreateShortcuts(const InstallOptions& o, std::wstring* log) {
    bool all = true;
    const std::wstring target = Join(o.installDir, kLauncherExe);
    if (o.desktopShortcut) {
        bool ok = CreateShortcut(Join(KnownFolder(FOLDERID_Desktop), L"KswordARK.lnk"), target, o.installDir);
        AppendLog(log, ok ? L"已创建桌面快捷方式。" : L"创建桌面快捷方式失败。");
        all = all && ok;
    }
    if (o.startMenuShortcut) {
        bool ok = CreateShortcut(Join(Join(KnownFolder(FOLDERID_Programs), L"KswordARK"), L"KswordARK.lnk"), target, o.installDir);
        AppendLog(log, ok ? L"已创建开始菜单快捷方式。" : L"创建开始菜单快捷方式失败。");
        all = all && ok;
    }
    return all;
}

// LaunchKsword starts the installed Launcher. Input is install directory;
// processing uses ShellExecuteW; output is true when launch is accepted.
bool LaunchKsword(const std::wstring& dir) {
    HINSTANCE rc = ::ShellExecuteW(nullptr, L"open", Join(dir, kLauncherExe).c_str(), nullptr, dir.c_str(), SW_SHOWNORMAL);
    return reinterpret_cast<INT_PTR>(rc) > 32;
}

// PerformInstall executes the full install transaction. Input is options;
// processing extracts payload, applies optional actions, prompts for reboot, and
// output is the final result model for follow-up launch/reboot behavior.
InstallResult PerformInstall(const InstallOptions& o) {
    InstallResult r;
    AppendLog(&r.logText, L"开始安装到: " + o.installDir);
    if (FileExistsInDir(o.installDir, kLauncherExe) || FileExistsInDir(o.installDir, kMainExe)) {
        AppendLog(&r.logText, L"检测到已有安装，按合并覆盖方式更新。");
    }
    r.ok = ExtractPayload(o, &r.logText) && r.ok;
    if (!r.ok) return r;
    r.ok = WriteSettings(o, &r.logText) && r.ok;
    r.ok = CreateShortcuts(o, &r.logText) && r.ok;
    if (o.replaceTaskmgr) r.ok = InstallTaskmgr(o, &r.logText) && r.ok;
    if (o.testMode) {
        const bool testOk = EnableTestMode(&r.logText);
        r.ok = testOk && r.ok;
        if (testOk) {
            SetInstallerShellDialogMode(true);
            int choice = TopMostMessageBox(L"测试模式已写入，需要重启系统后生效。是否立即重启？", L"KswordSetup", MB_ICONQUESTION | MB_YESNO | MB_DEFBUTTON2);
            SetInstallerShellDialogMode(false);
            r.rebootNow = choice == IDYES;
        }
    }
    AppendLog(&r.logText, r.ok ? L"安装完成。" : L"安装完成，但存在失败项，请查看日志。");
    return r;
}

// StartInstall handles the Install button and elevated continuation. Input is
// current UI state; processing performs UAC handoff when needed; no return.
void StartInstall() {
    InstallOptions o = CollectOptions();
    ShowInstallPage();
    SetStatus(L"准备安装...");
    if (NeedsElevation(o) && !IsElevated()) {
        SetStatus(L"当前选项需要管理员权限，正在请求 UAC...\r\n需要管理员权限的选项包括替换任务管理器或启动测试模式。");
        std::wstring state = TempStatePath();
        if (!SaveState(state, o)) {
            TopMostMessageBox(L"写入提权状态文件失败。", L"KswordSetup", MB_ICONERROR);
            ShowSetupPage();
            return;
        }
        if (RelaunchElevated(state)) {
            SetStatus(L"已请求管理员权限，请在 UAC 窗口确认。确认后安装将在新窗口继续。");
            return;
        }
        TopMostMessageBox(L"管理员权限请求被取消或启动失败。", L"KswordSetup", MB_ICONWARNING);
        ShowSetupPage();
        return;
    }
    if (g_installButton) g_installButton->deactivate();
    if (g_browseButton) g_browseButton->deactivate();
    InstallResult result = PerformInstall(o);
    if (g_installButton) g_installButton->activate();
    if (g_browseButton) g_browseButton->activate();
    if (result.rebootNow) {
        ::ShellExecuteW(nullptr, L"open", L"shutdown.exe", L"/r /t 0", nullptr, SW_HIDE);
        return;
    }
    if (result.ok && o.launchAfterInstall) LaunchKsword(o.installDir);
}

// BrowseInstallDir opens the native folder picker. Input is current UI path;
// processing uses IFileDialog in folder mode; no return value.
void BrowseInstallDir() {
    SetInstallerShellDialogMode(true);
    IFileDialog* dlg = nullptr;
    HRESULT hr = ::CoCreateInstance(CLSID_FileOpenDialog, nullptr, CLSCTX_INPROC_SERVER, IID_IFileDialog, (void**)&dlg);
    if (FAILED(hr) || !dlg) {
        SetInstallerShellDialogMode(false);
        return;
    }
    DWORD opts = 0;
    dlg->GetOptions(&opts);
    dlg->SetOptions(opts | FOS_PICKFOLDERS | FOS_FORCEFILESYSTEM);
    dlg->SetTitle(L"选择 KswordARK 安装目录");
    if (SUCCEEDED(dlg->Show(nullptr))) {
        IShellItem* item = nullptr;
        if (SUCCEEDED(dlg->GetResult(&item)) && item) {
            PWSTR raw = nullptr;
            if (SUCCEEDED(item->GetDisplayName(SIGDN_FILESYSPATH, &raw)) && raw) {
                if (g_pathInput) g_pathInput->value(WideToUtf8(raw).c_str());
                ::CoTaskMemFree(raw);
            }
            item->Release();
        }
    }
    dlg->Release();
    SetInstallerShellDialogMode(false);
}

// ExtractCharacterImage releases the left PNG to temp for KLayeredImageWindow.
// Input is none; processing extracts once; output is a UTF-8 filesystem path.
std::string ExtractCharacterImage() {
    if (!g_characterImagePath.empty() && ExistsFile(g_characterImagePath)) return WideToUtf8(g_characterImagePath);
    wchar_t temp[MAX_PATH]{};
    if (!::GetTempPathW(MAX_PATH, temp)) g_characterImagePath = L"KswordSetupCharacter.png";
    else g_characterImagePath = Join(temp, L"KswordSetupCharacter.png");
    ExtractRc(IDR_KSWORD_SETUP_CHARACTER_PNG, g_characterImagePath);
    return WideToUtf8(g_characterImagePath);
}

// ApplyInstallerZOrder keeps the installer panel and character image in the
// requested topmost order. When the compile-time switch is disabled, this
// becomes a no-op so the installer can be tested without any topmost behavior.
void ApplyInstallerZOrder(Fl_Window* owner) {
#if KSWORD_SETUP_ENABLE_TOPMOST
    if (!owner) return;
    HWND ownerHwnd = fl_win32_xid(owner);
    if (ownerHwnd) {
        ::SetWindowPos(ownerHwnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
    }
    HWND imageHwnd = g_characterWindow.hwnd();
    if (imageHwnd) {
        ::SetWindowPos(imageHwnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
    }
#else
    (void)owner;
#endif
}

// SetInstallerShellDialogMode temporarily disables the topmost behavior while a
// shell dialog is shown. When the compile-time switch is disabled, the helper
// stays inert and simply preserves the installer state.
void SetInstallerShellDialogMode(bool enabled) {
#if KSWORD_SETUP_ENABLE_TOPMOST
    g_topMostPaused = enabled;
    HWND ownerHwnd = g_mainWindow ? fl_win32_xid(g_mainWindow) : nullptr;
    HWND imageHwnd = g_characterWindow.hwnd();
    const HWND insertAfter = enabled ? HWND_NOTOPMOST : HWND_TOPMOST;
    const UINT flags = SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE;
    if (ownerHwnd) {
        ::SetWindowPos(ownerHwnd, insertAfter, 0, 0, 0, 0, flags);
    }
    if (imageHwnd) {
        ::SetWindowPos(imageHwnd, insertAfter, 0, 0, 0, 0, flags);
    }
    if (!enabled && g_mainWindow) {
        ApplyInstallerZOrder(g_mainWindow);
    }
#else
    (void)enabled;
#endif
}

// TopMostMessageBox shows a native message box above the installer. Inputs are
// normal MessageBoxW parameters; processing optionally adds MB_TOPMOST when the
// compile-time switch is enabled; output is the clicked button id.
int TopMostMessageBox(const wchar_t* text, const wchar_t* caption, UINT type) {
    HWND ownerHwnd = g_mainWindow ? fl_win32_xid(g_mainWindow) : nullptr;
#if KSWORD_SETUP_ENABLE_TOPMOST
    return ::MessageBoxW(ownerHwnd, text, caption, type | MB_TOPMOST | MB_SETFOREGROUND);
#else
    return ::MessageBoxW(ownerHwnd, text, caption, type | MB_SETFOREGROUND);
#endif
}

// EnsureTaskbarAppWindow makes the FLTK owner a normal shell application window.
// Input is the right-side installer window; processing removes tool/noactivate
// styles and forces WS_EX_APPWINDOW; no value is returned.
void EnsureTaskbarAppWindow(Fl_Window* window) {
    HWND hwnd = window ? fl_win32_xid(window) : nullptr;
    if (!hwnd) return;
    LONG_PTR exStyle = ::GetWindowLongPtrW(hwnd, GWL_EXSTYLE);
    exStyle &= ~(static_cast<LONG_PTR>(WS_EX_TOOLWINDOW) | static_cast<LONG_PTR>(WS_EX_NOACTIVATE));
    exStyle |= WS_EX_APPWINDOW;
    ::SetWindowLongPtrW(hwnd, GWL_EXSTYLE, exStyle);
    ::SetWindowLongPtrW(hwnd, GWLP_HWNDPARENT, 0);
    ::SetWindowPos(hwnd, nullptr, 0, 0, 0, 0,
        SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOOWNERZORDER | SWP_NOACTIVATE | SWP_FRAMECHANGED);
}

// ReassertInstallerZOrder is a low-frequency FLTK timer callback. Input is the
// owner window pointer; processing reapplies z-order after activation/focus
// churn; no value is returned and the timer stops once the owner closes.
void ReassertInstallerZOrder(void* data) {
    auto* owner = static_cast<Fl_Window*>(data);
    if (!owner || !owner->shown()) return;
#if KSWORD_SETUP_ENABLE_TOPMOST
    if (!g_topMostPaused) {
        ApplyInstallerZOrder(owner);
    }
    Fl::repeat_timeout(0.75, ReassertInstallerZOrder, data);
#endif
}

// ParseStateArgument returns the --install-state path. Input is process command
// line; processing tokenizes with CommandLineToArgvW; output is empty when absent.
std::wstring ParseStateArgument() {
    int argc = 0;
    LPWSTR* argv = ::CommandLineToArgvW(::GetCommandLineW(), &argc);
    if (!argv) return {};
    std::wstring out;
    for (int i = 1; i + 1 < argc; ++i) {
        if (std::wstring(argv[i]) == kStateArg) { out = argv[i + 1]; break; }
    }
    ::LocalFree(argv);
    return out;
}

// ConfigureRightContent builds the installer page. Input is owner window;
// processing creates K* widgets and callbacks; no return value.
void ConfigureRightContent(Fl_Window* window) {
    const KTheme& theme = KThemeManager::instance().theme();
    const PageLayout layout = BuildPageLayout();

    g_setupPage = KCreateCard(layout.cardX, layout.cardY, layout.cardW, layout.cardH, nullptr);
    g_setupPage->setTitle("");
    g_setupPage->setSubtitle("");
    g_setupPage->begin();
    KText* headerTitle = KCreateText(layout.contentX, layout.cardY + 22, layout.contentW, 26, "KswordSetup");
    headerTitle->labelsize(19);
    headerTitle->labelcolor(theme.text);
    KText* headerSubtitle = KCreateText(layout.contentX, layout.cardY + 46, layout.contentW, 22, "选择安装路径和首次启动行为，点击安装时按需请求管理员权限。");
    headerSubtitle->labelsize(13);
    headerSubtitle->labelcolor(theme.mutedText);
    KText* title = KCreateText(layout.contentX, layout.cardY + 82, layout.contentW, 26, "安装路径");
    title->labelsize(19);
    title->labelcolor(theme.text);
    g_pathInput = KCreateInput(layout.contentX, layout.cardY + 108, layout.contentW - 112, 30, nullptr);
    g_pathInput->value(WideToUtf8(DefaultInstallDir()).c_str());
    g_browseButton = KCreateButton(layout.contentX + layout.contentW - 94, layout.cardY + 108, 94, 30, "浏览", KBUTTON_LIGHT);
    g_browseButton->callback([](Fl_Widget*, void*) { BrowseInstallDir(); });
    int y = layout.cardY + 150;
    g_adminCheck = KCreateCheckBox(layout.contentX, y, layout.contentW, 24, "启动时自动请求管理员权限"); g_adminCheck->value(1); y += 27;
    g_maxCheck = KCreateCheckBox(layout.contentX, y, layout.contentW, 24, "启动时默认最大化"); g_maxCheck->value(1); y += 27;
    g_taskmgrCheck = KCreateCheckBox(layout.contentX, y, layout.contentW, 24, "替换系统自带任务管理器（需要管理员权限）"); y += 27;
    g_testModeCheck = KCreateCheckBox(layout.contentX, y, layout.contentW, 24, "启动测试模式 testsigning（需要管理员权限）"); y += 27;
    g_desktopCheck = KCreateCheckBox(layout.contentX, y, layout.contentW, 24, "创建桌面快捷方式"); g_desktopCheck->value(1); y += 27;
    g_startMenuCheck = KCreateCheckBox(layout.contentX, y, layout.contentW, 24, "创建开始菜单快捷方式"); g_startMenuCheck->value(1);
    g_installButton = KCreateButton(layout.contentX + layout.contentW - 224, layout.cardY + layout.cardH - 48, 104, 34, "安装", KBUTTON_HEAVY);
    g_installButton->callback([](Fl_Widget*, void*) { StartInstall(); });
    KButton* closeButton = KCreateButton(layout.contentX + layout.contentW - 104, layout.cardY + layout.cardH - 48, 100, 34, "关闭", KBUTTON_LIGHT);
    closeButton->callback([](Fl_Widget*, void* data) {
        g_characterWindow.destroy();
        if (auto* owner = static_cast<Fl_Window*>(data)) owner->hide();
    }, window);
    g_setupPage->end();

    g_installPage = KCreateCard(layout.cardX, layout.cardY, layout.cardW, layout.cardH, nullptr);
    g_installPage->setTitle("");
    g_installPage->setSubtitle("");
    g_installPage->begin();
    KText* installTitle = KCreateText(layout.contentX, layout.cardY + 22, layout.contentW, 28, "安装进度");
    installTitle->labelsize(19);
    installTitle->labelcolor(theme.text);
    KText* installSubtitle = KCreateText(layout.contentX, layout.cardY + 48, layout.contentW, 22, "安装时会释放内嵌 payload，并在需要时执行管理员操作。");
    installSubtitle->labelsize(13);
    installSubtitle->labelcolor(theme.mutedText);
    g_status = KCreateTextDisplay(layout.contentX, layout.cardY + 86, layout.contentW, 250, nullptr);
    g_status->set_text("等待开始安装。");
    g_launchCheck = KCreateCheckBox(layout.contentX, layout.cardY + 350, layout.contentW, 24, "安装完成后启动 Ksword");
    g_launchCheck->value(1);
    KButton* backButton = KCreateButton(layout.contentX + layout.contentW - 224, layout.cardY + layout.cardH - 48, 104, 34, "返回", KBUTTON_LIGHT);
    backButton->callback([](Fl_Widget*, void*) { ShowSetupPage(); });
    KButton* finishButton = KCreateButton(layout.contentX + layout.contentW - 104, layout.cardY + layout.cardH - 48, 100, 34, "关闭", KBUTTON_LIGHT);
    finishButton->callback([](Fl_Widget*, void* data) {
        g_characterWindow.destroy();
        if (auto* owner = static_cast<Fl_Window*>(data)) owner->hide();
    }, window);
    g_installPage->end();
    g_installPage->hide();
}
} // namespace

// GuiInitMain builds the right-side FLTK installer content. Inputs are arguments
// and the owner window; processing sets style and widgets; no value is returned.
void GuiInitMain(const std::vector<std::string>& args, Fl_Window* MainWindow) {
    (void)args;
    if (!MainWindow) return;
    g_mainWindow = MainWindow;
    MainWindow->label("KswordSetup");
    MainWindow->size(kWindowWidth, kWindowHeight);
    MainWindow->border(0);
    SetWindowStyle(MainWindow);
    ConfigureRightContent(MainWindow);
    KThemeManager::instance().RefreshAll();
}

// GuiAfterShowMain creates the transparent left PNG window and starts elevated
// continuation when --install-state is present. Input is the shown owner window;
// no value is returned.
void GuiAfterShowMain(Fl_Window* MainWindow) {
    if (!MainWindow) return;
    EnsureTaskbarAppWindow(MainWindow);
    const std::string characterPath = ExtractCharacterImage();
    g_characterWindow.setClickThrough(true);
    g_characterWindow.showPngForWindow(MainWindow, characterPath, -kLayeredImageWidth + kImageOverlap, -kImageVerticalOffset, kLayeredImageWidth, kImageDrawHeight);
    ApplyInstallerZOrder(MainWindow);
    Fl::add_timeout(0.75, ReassertInstallerZOrder, MainWindow);
    const std::wstring state = ParseStateArgument();
    if (!state.empty()) {
        ApplyOptions(LoadState(state));
        ::DeleteFileW(state.c_str());
        SetStatus(L"已获得管理员权限，正在继续安装...");
        Fl::add_timeout(0.20, [](void*) { StartInstall(); });
    }
}

// AsyncMain remains present for the framework entry point contract. Input args
// are unused by the installer background thread; output zero means success.
int AsyncMain(const std::vector<std::string>& args) {
    (void)args;
    return 0;
}

