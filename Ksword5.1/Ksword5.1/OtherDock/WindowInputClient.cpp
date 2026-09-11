#include "WindowInputClient.h"
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include <map>

namespace ks::window_input
{
    namespace
    {
        struct Saved
        {
            dwm_order::WindowIdentity identity;
            LONG_PTR originalStyle = 0;
            LONG_PTR originalExStyle = 0;
            LONG_PTR changedExMask = 0;
            Mode mode = Mode::Unchanged;
            HANDLE cookie = nullptr;
            bool changedEnabled = false;
            bool changedTopmost = false;
            bool changedDwm = false;
            bool layerAttributesInitialized = false;
        };
        std::map<std::uint64_t, Saved> savedWindows;
        std::uintptr_t nextCookie = 0;

        const wchar_t* PropertyName()
        {
            static const std::wstring name = L"KSword.WindowInput."
                + std::to_wstring(GetCurrentProcessId()) + L"." + std::to_wstring(GetTickCount64());
            return name.c_str();
        }

        HWND Window(const dwm_order::WindowIdentity& identity)
        { return reinterpret_cast<HWND>(identity.hwnd); }

        bool Same(const dwm_order::WindowIdentity& expected)
        {
            dwm_order::WindowIdentity current;
            std::uint32_t error = 0;
            return Capture(expected.hwnd, current, error)
                && current.processId == expected.processId && current.threadId == expected.threadId
                && current.processCreated == expected.processCreated;
        }

        bool Alive(const Saved& saved)
        {
            // A HWND may be reused by the same process/thread. A property belongs
            // to the actual window object and disappears when that object dies.
            return Same(saved.identity) && GetPropW(Window(saved.identity), PropertyName()) == saved.cookie;
        }

        void Prune()
        {
            for (auto it = savedWindows.begin(); it != savedWindows.end();)
                if (!Alive(it->second)) it = savedWindows.erase(it);
                else ++it;
        }

        bool ReadLong(HWND hwnd, int index, LONG_PTR& value, std::uint32_t& error)
        {
            SetLastError(ERROR_SUCCESS);
            value = GetWindowLongPtrW(hwnd, index);
            error = GetLastError();
            return value != 0 || error == ERROR_SUCCESS;
        }

        bool WriteLong(HWND hwnd, int index, LONG_PTR value, std::uint32_t& error)
        {
            SetLastError(ERROR_SUCCESS);
            const LONG_PTR previous = SetWindowLongPtrW(hwnd, index, value);
            error = GetLastError();
            LONG_PTR actual = 0;
            if ((!previous && error) || !ReadLong(hwnd, index, actual, error)) return false;
            if (actual != value) { error = ERROR_INVALID_DATA; return false; }
            return true;
        }

        bool SetEnabled(HWND hwnd, bool enabled, std::uint32_t& error)
        {
            SetLastError(ERROR_SUCCESS);
            // EnableWindow returns the PREVIOUS disabled state, not success.
            EnableWindow(hwnd, enabled ? TRUE : FALSE);
            error = GetLastError();
            LONG_PTR style = 0;
            std::uint32_t readError = 0;
            if (!ReadLong(hwnd, GWL_STYLE, style, readError)) { error = readError; return false; }
            if (((style & WS_DISABLED) == 0) != enabled)
            { if (!error) error = ERROR_ACCESS_DENIED; return false; }
            error = 0;
            return true;
        }

        bool SetTopmost(HWND hwnd, bool topmost, std::uint32_t& error)
        {
            if (!SetWindowPos(hwnd, topmost ? HWND_TOPMOST : HWND_NOTOPMOST, 0, 0, 0, 0,
                SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE | SWP_NOOWNERZORDER))
            { error = GetLastError(); return false; }
            LONG_PTR exStyle = 0;
            if (!ReadLong(hwnd, GWL_EXSTYLE, exStyle, error)) return false;
            if (((exStyle & WS_EX_TOPMOST) != 0) != topmost)
            { error = ERROR_INVALID_DATA; return false; }
            return true;
        }

        Result ReadState(const dwm_order::WindowIdentity& identity)
        {
            Result result;
            if (!Same(identity))
            { result.status = Status::InvalidWindow; result.error = ERROR_INVALID_WINDOW_HANDLE; return result; }
            LONG_PTR style = 0, exStyle = 0;
            if (!ReadLong(Window(identity), GWL_STYLE, style, result.error)
                || !ReadLong(Window(identity), GWL_EXSTYLE, exStyle, result.error))
            { result.status = Status::NativeFailure; return result; }
            result.enabled = (style & WS_DISABLED) == 0;
            result.clickThrough = (exStyle & (WS_EX_LAYERED | WS_EX_TRANSPARENT))
                == (WS_EX_LAYERED | WS_EX_TRANSPARENT);
            result.topmost = (exStyle & WS_EX_TOPMOST) != 0;
            auto it = savedWindows.find(identity.hwnd);
            if (it != savedWindows.end() && Alive(it->second))
            { result.managed = true; result.mode = it->second.mode; }
            return result;
        }

        bool RestoreSaved(Saved& saved, const std::wstring& agentPath, Result& result)
        {
            if (!Alive(saved)) return true; // Do not touch a replacement window.
            const HWND hwnd = Window(saved.identity);
            if (saved.changedTopmost)
            {
                if (!SetTopmost(hwnd, (saved.originalExStyle & WS_EX_TOPMOST) != 0, result.error)) return false;
                saved.changedTopmost = false;
            }
            if (saved.changedDwm)
            {
                dwm_order::Request request;
                request.action = dwm_order::Action::Restore;
                request.target = saved.identity;
                result.dwmAttempted = true;
                result.dwm = dwm_order::ExecuteRequest(request, agentPath);
                if (result.dwm.response.status != dwm_order::Status::NotRunning
                    && (result.dwm.response.status != dwm_order::Status::Ok
                        || !(result.dwm.response.flags & dwm_order::Verified))) return false;
                saved.changedDwm = false;
            }
            if (!Alive(saved)) return true;
            if (saved.changedEnabled)
            {
                if (!SetEnabled(hwnd, (saved.originalStyle & WS_DISABLED) == 0, result.error)) return false;
                saved.changedEnabled = false;
            }
            if (saved.changedExMask)
            {
                LONG_PTR current = 0;
                if (!ReadLong(hwnd, GWL_EXSTYLE, current, result.error)) return false;
                LONG_PTR restoreMask = saved.changedExMask;
                if ((restoreMask & WS_EX_LAYERED) && saved.layerAttributesInitialized)
                {
                    COLORREF color = 0;
                    BYTE alpha = 0;
                    DWORD flags = 0;
                    // Preserve layering if the target has since adopted its own
                    // attributes or per-pixel rendering. We own only alpha=255.
                    if (!GetLayeredWindowAttributes(hwnd, &color, &alpha, &flags)
                        || flags != LWA_ALPHA || alpha != 255)
                        restoreMask &= ~static_cast<LONG_PTR>(WS_EX_LAYERED);
                }
                if (!WriteLong(hwnd, GWL_EXSTYLE,
                    (current & ~restoreMask) | (saved.originalExStyle & restoreMask), result.error)) return false;
                saved.changedExMask = 0;
                RedrawWindow(hwnd, nullptr, nullptr, RDW_INVALIDATE | RDW_FRAME | RDW_ALLCHILDREN);
            }
            RemovePropW(hwnd, PropertyName());
            return true;
        }
    }

    bool Capture(std::uint64_t hwndValue, dwm_order::WindowIdentity& identity, std::uint32_t& error)
    {
        identity = {};
        const HWND hwnd = reinterpret_cast<HWND>(hwndValue);
        DWORD pid = 0;
        const DWORD tid = GetWindowThreadProcessId(hwnd, &pid);
        if (!hwnd || !tid || !pid) { error = ERROR_INVALID_WINDOW_HANDLE; return false; }
        HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!process) { error = GetLastError(); return false; }
        FILETIME created{}, exited{}, kernel{}, user{};
        const bool ok = GetProcessTimes(process, &created, &exited, &kernel, &user) != FALSE;
        error = ok ? ERROR_SUCCESS : GetLastError();
        CloseHandle(process);
        if (!ok) return false;
        DWORD checkedPid = 0;
        if (GetWindowThreadProcessId(hwnd, &checkedPid) != tid || checkedPid != pid)
        { error = ERROR_INVALID_WINDOW_HANDLE; return false; }
        identity = {hwndValue, pid, tid,
            (static_cast<std::uint64_t>(created.dwHighDateTime) << 32) | created.dwLowDateTime};
        return true;
    }

    Result Query(const dwm_order::WindowIdentity& identity, const std::wstring& agentPath)
    {
        const std::lock_guard<std::recursive_mutex> lock(dwm_order::OperationMutex());
        Prune();
        Result result = ReadState(identity);
        if (result.status == Status::Ok && result.managed && result.mode == Mode::Covered)
        {
            dwm_order::Request request;
            request.target = identity;
            result.dwmAttempted = true;
            result.dwm = dwm_order::ExecuteRequest(request, agentPath);
            if (result.dwm.response.status != dwm_order::Status::Ok)
                result.status = Status::DwmFailure;
            else if (!result.topmost || !(result.dwm.response.flags & dwm_order::Verified)
                || !(result.dwm.response.flags & dwm_order::Maintaining)
                || result.dwm.response.maintainedWindow != identity.hwnd)
                result.status = Status::OrderChanged;
        }
        return result;
    }

    Result Restore(const dwm_order::WindowIdentity& identity, const std::wstring& agentPath)
    {
        const std::lock_guard<std::recursive_mutex> lock(dwm_order::OperationMutex());
        Result result;
        auto it = savedWindows.find(identity.hwnd);
        const bool hadRecord = it != savedWindows.end();
        if (it != savedWindows.end())
        {
            if (identity.processId != it->second.identity.processId
                || identity.threadId != it->second.identity.threadId
                || identity.processCreated != it->second.identity.processCreated)
            { result.status = Status::InvalidWindow; result.error = ERROR_INVALID_WINDOW_HANDLE; return result; }
            if (!RestoreSaved(it->second, agentPath, result))
            { result.status = Status::RestoreFailed; return result; }
            savedWindows.erase(it);
        }
        result = ReadState(identity);
        result.restored = hadRecord;
        return result;
    }

    Result Apply(const dwm_order::WindowIdentity& identity, Mode mode, const std::wstring& agentPath)
    {
        const std::lock_guard<std::recursive_mutex> lock(dwm_order::OperationMutex());
        Prune();
        Result result = ReadState(identity);
        if (result.status != Status::Ok) return result;
        if (identity.processId == GetCurrentProcessId()) { result.status = Status::SelfWindow; return result; }
        if (mode == Mode::Unchanged) return Restore(identity, agentPath);
        if (result.managed)
        {
            result = Restore(identity, agentPath);
            if (result.status != Status::Ok) return result;
        }
        if (savedWindows.size() >= 128) { result.status = Status::LimitReached; return result; }
        const HWND hwnd = Window(identity);
        Saved saved;
        saved.identity = identity;
        saved.mode = mode;
        if (!ReadLong(hwnd, GWL_STYLE, saved.originalStyle, result.error)
            || !ReadLong(hwnd, GWL_EXSTYLE, saved.originalExStyle, result.error))
        { result.status = Status::NativeFailure; return result; }
        if (mode == Mode::ClickThrough && !(saved.originalExStyle & WS_EX_LAYERED)
            && (GetClassLongPtrW(hwnd, GCL_STYLE) & (CS_OWNDC | CS_CLASSDC)))
        { result.status = Status::UnsupportedWindow; return result; }
        if (mode == Mode::Covered)
        {
            if (GetAncestor(hwnd, GA_ROOT) != hwnd || GetWindow(hwnd, GW_OWNER)
                || !result.enabled || (saved.originalExStyle & WS_EX_TRANSPARENT)
                || !IsWindowVisible(hwnd) || IsIconic(hwnd))
            { result.status = Status::UnsupportedWindow; return result; }
            dwm_order::Request request;
            request.target = identity;
            result.dwmAttempted = true;
            result.dwm = dwm_order::ExecuteRequest(request, agentPath);
            if (result.dwm.response.status != dwm_order::Status::Ok
                || !(result.dwm.response.flags & dwm_order::Verified))
            { result.status = Status::DwmFailure; return result; }
            if (result.dwm.response.flags & dwm_order::Maintaining)
            { result.status = Status::OrderInUse; return result; }
        }
        saved.cookie = reinterpret_cast<HANDLE>(++nextCookie);
        if (!Same(identity))
        { result.status = Status::InvalidWindow; result.error = ERROR_INVALID_WINDOW_HANDLE; return result; }
        if (!SetPropW(hwnd, PropertyName(), saved.cookie))
        { result.status = Status::NativeFailure; result.error = GetLastError(); return result; }
        auto& record = savedWindows.emplace(identity.hwnd, saved).first->second;
        bool ok = false;
        if (mode == Mode::Disabled)
        {
            record.changedEnabled = (record.originalStyle & WS_DISABLED) == 0;
            ok = SetEnabled(hwnd, false, result.error);
        }
        else if (mode == Mode::ClickThrough)
        {
            const LONG_PTR desired = record.originalExStyle | WS_EX_LAYERED | WS_EX_TRANSPARENT;
            record.changedExMask = desired ^ record.originalExStyle;
            ok = WriteLong(hwnd, GWL_EXSTYLE, desired, result.error);
            if (ok && (record.changedExMask & WS_EX_LAYERED))
            {
                ok = SetLayeredWindowAttributes(hwnd, 0, 255, LWA_ALPHA) != FALSE;
                record.layerAttributesInitialized = ok;
                if (!ok) result.error = GetLastError();
            }
        }
        else if (mode == Mode::Covered)
        {
            record.changedTopmost = (record.originalExStyle & WS_EX_TOPMOST) == 0;
            ok = SetTopmost(hwnd, true, result.error);
            if (ok)
            {
                dwm_order::Request request;
                request.action = dwm_order::Action::Apply;
                request.target = identity;
                request.position = dwm_order::Position::Back;
                request.maintain = 1;
                record.changedDwm = true; // A timeout can still have applied the request.
                result.dwmAttempted = true;
                result.dwm = dwm_order::ExecuteRequest(request, agentPath);
                ok = result.dwm.response.status == dwm_order::Status::Ok
                    && (result.dwm.response.flags & dwm_order::Verified)
                    && (result.dwm.response.flags & dwm_order::Maintaining)
                    && result.dwm.response.maintainedWindow == identity.hwnd;
                if (!ok) result.status = Status::DwmFailure;
            }
        }
        if (ok && Alive(record))
        {
            Result current = ReadState(identity);
            if (current.status == Status::Ok
                && (mode != Mode::Disabled || !current.enabled)
                && (mode != Mode::ClickThrough || current.clickThrough)
                && (mode != Mode::Covered || current.topmost)) return current;
        }
        if (result.status == Status::Ok) result.status = Status::NativeFailure;
        Result rollback;
        if (RestoreSaved(record, agentPath, rollback)) savedWindows.erase(identity.hwnd);
        else
        {
            result.status = Status::RestoreFailed;
            result.error = rollback.error;
            if (rollback.dwmAttempted) { result.dwm = rollback.dwm; result.dwmAttempted = true; }
        }
        return result;
    }

    Result RestoreAll(const std::wstring& agentPath)
    {
        const std::lock_guard<std::recursive_mutex> lock(dwm_order::OperationMutex());
        Result firstFailure;
        for (auto it = savedWindows.begin(); it != savedWindows.end();)
        {
            Result result;
            if (RestoreSaved(it->second, agentPath, result)) it = savedWindows.erase(it);
            else
            {
                result.status = Status::RestoreFailed;
                if (firstFailure.status == Status::Ok) firstFailure = result;
                ++it;
            }
        }
        return firstFailure;
    }

    bool HasCoveredWindow()
    {
        const std::lock_guard<std::recursive_mutex> lock(dwm_order::OperationMutex());
        Prune();
        for (const auto& [hwnd, saved] : savedWindows)
        {
            (void)hwnd;
            if (saved.changedDwm) return true;
        }
        return false;
    }
}
