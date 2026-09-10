#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

extern "C" const unsigned char DwmPrivateFind[], DwmPrivateDesktop[];
extern "C" __declspec(dllexport) void WINAPI DwmQueryFixtureAddresses(const void** find, const void** desktop)
{ *find = DwmPrivateFind; *desktop = DwmPrivateDesktop; }

BOOL WINAPI DllMain(HMODULE module, DWORD reason, void*)
{
    if (reason != DLL_PROCESS_ATTACH) return TRUE;
    wchar_t path[MAX_PATH]{};
    if (!GetModuleFileNameW(module, path, MAX_PATH)) return FALSE;
    const wchar_t* name = path;
    for (const wchar_t* at = path; *at; ++at) if (*at == L'\\') name = at + 1;
    if (lstrcmpiW(name, L"DwmLoaderReject.dll") == 0) return FALSE;

    HANDLE token = nullptr;
    if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &token))
        return GetLastError() == ERROR_NO_TOKEN;
    CloseHandle(token);
    return FALSE;
}
