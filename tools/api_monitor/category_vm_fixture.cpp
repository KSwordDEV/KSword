#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincrypt.h>
#include <objbase.h>
#include <bcrypt.h>
#include <string>

static bool exists(const std::wstring& p) { return GetFileAttributesW(p.c_str()) != INVALID_FILE_ATTRIBUTES; }
static void touch(const std::wstring& p) { HANDLE h=CreateFileW(p.c_str(),GENERIC_WRITE,FILE_SHARE_READ,nullptr,CREATE_ALWAYS,0,nullptr); if(h!=INVALID_HANDLE_VALUE) CloseHandle(h); }
int wmain(int argc, wchar_t** argv) {
    if(argc<2) return 2;
    const std::wstring root=argv[1]; const bool child=argc>2;
    // Fail visibly if the fixture cannot exercise the successful return paths.
    HMODULE user=LoadLibraryW(L"user32.dll"); HMODULE ole=LoadLibraryW(L"ole32.dll"); HMODULE adv=LoadLibraryW(L"advapi32.dll");
    if(!user || !ole || !adv) return 3;
    HWND window=CreateWindowExW(0,L"STATIC",L"KSword category fixture",0,0,0,32,32,nullptr,nullptr,GetModuleHandleW(nullptr),nullptr);
    if(!window) return 11;
    HDC drawing=CreateCompatibleDC(nullptr);
    HBITMAP bitmap=CreateBitmap(32,32,1,32,nullptr);
    HGDIOBJ previous=drawing && bitmap?SelectObject(drawing,bitmap):nullptr;
    if(!drawing || !bitmap || !previous || previous==HGDI_ERROR) return 22;
    BCRYPT_ALG_HANDLE algorithm=nullptr;
    if(BCryptOpenAlgorithmProvider(&algorithm,BCRYPT_SHA256_ALGORITHM,nullptr,0)<0) return 12;
    touch(root+(child?L"\\child-ready":L"\\ready"));
    bool spawned=false;
    while(!exists(root+L"\\stop")) {
        if(!child && !spawned && exists(root+L"\\spawn")) {
            spawned=true; wchar_t exe[MAX_PATH]{}; GetModuleFileNameW(nullptr,exe,MAX_PATH);
            std::wstring command=L"\""+std::wstring(exe)+L"\" \""+root+L"\" child";
            STARTUPINFOW si{};si.cb=sizeof(si); PROCESS_INFORMATION pi{};
            if(!CreateProcessW(exe,command.data(),nullptr,nullptr,FALSE,CREATE_NO_WINDOW,nullptr,nullptr,&si,&pi)) return 4;
            CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        }
        void* mem=VirtualAlloc(nullptr,4096,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);
        if(!mem || !VirtualFree(mem,0,MEM_RELEASE)) return 5;
        SIZE_T minimum=0,maximum=0; if(!GetProcessWorkingSetSize(GetCurrentProcess(),&minimum,&maximum)) return 13;
        BOOL boost=FALSE; if(!GetThreadPriorityBoost(GetCurrentThread(),&boost)) return 14;
        SECURITY_DESCRIPTOR descriptor{}; if(!InitializeSecurityDescriptor(&descriptor,SECURITY_DESCRIPTOR_REVISION)) return 15;
        BOOL present=FALSE, defaulted=FALSE; PACL dacl=nullptr;
        if(!GetSecurityDescriptorDacl(&descriptor,&present,&dacl,&defaulted)) return 20;
        RECT rect{}; if(!GetWindowRect(window,&rect)) return 16;
        if(!BitBlt(drawing,0,0,1,1,drawing,0,0,SRCCOPY)) return 23;
        TEXTMETRICW metrics{};if(!GetTextMetricsW(drawing,&metrics)) return 24;
        (void)GetBkMode(drawing);(void)GetMapMode(drawing);
        (void)GetPolyFillMode(drawing);(void)GetROP2(drawing);
        GUID guid{}; if(FAILED(CoCreateGuid(&guid))) return 17;
        ULONG length=0, resultLength=0;
        if(BCryptGetProperty(algorithm,BCRYPT_HASH_LENGTH,reinterpret_cast<PUCHAR>(&length),sizeof(length),&resultLength,0)<0 || !length) return 18;
        SERVICE_STATUS serviceStatus{}; if(QueryServiceStatus(nullptr,&serviceStatus)) return 19;
        HANDLE thread=OpenThread(THREAD_QUERY_LIMITED_INFORMATION,FALSE,GetCurrentThreadId());
        if(!thread) return 6; CloseHandle(thread);
        SC_HANDLE scm=OpenSCManagerW(nullptr,nullptr,SC_MANAGER_CONNECT);
        if(!scm) return 7; CloseServiceHandle(scm);
        HANDLE token=nullptr; if(!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token)) return 8;
        TOKEN_TYPE tokenType{}; DWORD tokenLength=0;
        if(!GetTokenInformation(token,TokenType,&tokenType,sizeof(tokenType),&tokenLength)) return 21;
        CloseHandle(token);
        HCRYPTPROV provider=0; if(!CryptAcquireContextW(&provider,nullptr,nullptr,PROV_RSA_FULL,CRYPT_VERIFYCONTEXT)) return 9;
        CryptReleaseContext(provider,0);
        HRESULT hr=CoInitializeEx(nullptr,COINIT_APARTMENTTHREADED); if(FAILED(hr)) return 10; CoUninitialize();
        (void)GetForegroundWindow();
        Sleep(100);
    }
    SelectObject(drawing,previous);DeleteObject(bitmap);DeleteDC(drawing);
    BCryptCloseAlgorithmProvider(algorithm,0); DestroyWindow(window);
    return 0;
}
