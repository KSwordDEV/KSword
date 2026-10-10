#include "EtwFixture.h"
#include <Windows.h>
#include <evntprov.h>
#include <sstream>
#include <string>
#include <cstdint>
namespace {
const GUID provider={0x3ba8f5d1,0x14c1,0x4d13,{0xb8,0x19,0x4c,0xf3,0x91,0x88,0x67,0xc2}};
bool publish(const std::wstring& path,ULONG registration,ULONG write,ULONG close,std::uint64_t count,bool closed){
    std::ostringstream text;text<<"{\"pid\":"<<GetCurrentProcessId()<<",\"provider\":\"{3BA8F5D1-14C1-4D13-B819-4CF3918867C2}\",\"registerError\":"<<registration<<",\"writeError\":"<<write<<",\"closeError\":"<<close<<",\"writes\":\""<<count<<"\",\"unregistered\":"<<(closed?"true":"false")<<"}";
    const auto bytes=text.str();const auto temporary=path+L".tmp";const auto file=CreateFileW(temporary.c_str(),GENERIC_WRITE,FILE_SHARE_READ,nullptr,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,nullptr);if(file==INVALID_HANDLE_VALUE)return false;
    DWORD written=0;const bool ok=WriteFile(file,bytes.data(),static_cast<DWORD>(bytes.size()),&written,nullptr)&&written==bytes.size();CloseHandle(file);
    if(!ok)return false;for(int attempt=0;attempt<20;++attempt){if(MoveFileExW(temporary.c_str(),path.c_str(),MOVEFILE_REPLACE_EXISTING))return true;Sleep(5);}return false;
}
}
int RunEtwFixture(const wchar_t* statePath){
    const std::wstring path=statePath;REGHANDLE handle=0;const auto registration=EventRegister(&provider,nullptr,nullptr,&handle);
    std::uint64_t count=0;ULONG status=ERROR_SUCCESS;if(!publish(path,registration,status,0,count,false)){if(handle)EventUnregister(handle);return ERROR_WRITE_FAULT;}
    if(registration!=ERROR_SUCCESS)return static_cast<int>(registration);
    EVENT_DESCRIPTOR descriptor{};descriptor.Id=31000;descriptor.Level=4;descriptor.Keyword=1;
    while(count<3000&&GetFileAttributesW((path+L".stop").c_str())==INVALID_FILE_ATTRIBUTES){
        status=EventWrite(handle,&descriptor,0,nullptr);++count;if(status!=ERROR_SUCCESS)break;
        if(!publish(path,registration,status,0,count,false))break;Sleep(20);
    }
    const auto closed=EventUnregister(handle);publish(path,registration,status,closed,count,closed==ERROR_SUCCESS);return static_cast<int>(status?status:closed);
}
