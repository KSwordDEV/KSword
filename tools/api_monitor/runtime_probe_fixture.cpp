#include "runtime_probe_support.h"
#include "runtime_probe_window.inc"
#include "runtime_probe_memory_thread.inc"
#include "runtime_probe_service_security.inc"
#include "runtime_probe_gui_objects.inc"
#include "runtime_probe_gui_drawing.inc"

static bool Exists(const std::wstring& path) { return GetFileAttributesW(path.c_str())!=INVALID_FILE_ATTRIBUTES; }
static bool Touch(const std::wstring& path) {
    HANDLE file=CreateFileW(path.c_str(),GENERIC_WRITE,FILE_SHARE_READ,nullptr,CREATE_ALWAYS,0,nullptr);
    if(file==INVALID_HANDLE_VALUE)return false;CloseHandle(file);return true;
}
int wmain(int argc,wchar_t** argv) {
    if(argc!=3)return 2;
    wchar_t computer[MAX_COMPUTERNAME_LENGTH+1]{};DWORD length=MAX_COMPUTERNAME_LENGTH+1;
    if(!GetComputerNameW(computer,&length) || _wcsicmp(computer,L"DESKTOP-D2161R7")!=0)return 3;
    apimon_probe::g_allowGlobalStateChanges=true;
    apimon_probe::g_root=argv[1];const std::wstring group=argv[2];
    void (*run)()=group==L"window"?&apimon_probe::RunWindowCases:
        group==L"memory-thread"?&apimon_probe::RunMemoryThreadCases:
        group==L"service-security"?&apimon_probe::RunServiceSecurityCases:
        group==L"gui-objects"?&apimon_probe::RunGuiObjectCases:
        group==L"gui-drawing"?&apimon_probe::RunGuiDrawingCases:nullptr;
    if(!run)return 4;
    if(_wfopen_s(&apimon_probe::g_trace,(apimon_probe::g_root+L"\\trace.tsv").c_str(),L"w")!=0)return 5;
    run(); // Unhooked baseline, useful independently of event coverage.
    if(!Touch(apimon_probe::g_root+L"\\ready"))return 6;
    while(!Exists(apimon_probe::g_root+L"\\stop")) {
        if(Exists(apimon_probe::g_root+L"\\go")) { ++apimon_probe::g_round;run(); }
        Sleep(500);
    }
    std::fclose(apimon_probe::g_trace);apimon_probe::g_trace=nullptr;return 0;
}
