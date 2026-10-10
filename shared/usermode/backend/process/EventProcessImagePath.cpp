#include "EventProcessImagePath.h"
#include <vector>
namespace ks::r3::process {
std::wstring SampleProcessImage(std::uint32_t pid,DWORD capacity,ULONGLONG expected,ProcessImageEvidence& e){e={};e.capacity=capacity;if(capacity<2||capacity>32768){e.malformed=true;return {};}if(!pid)return {};HANDLE process=::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,pid);if(!process){e.openError=::GetLastError();return {};}
    e.opened=true;struct Owner{HANDLE handle;ProcessImageEvidence& e;~Owner(){e.closeAttempted=true;::SetLastError(0);e.closed=::CloseHandle(handle)!=FALSE;e.closeError=e.closed?0: ::GetLastError();}} owner{process,e};
    if(expected){FILETIME c{},x{},k{},u{};e.timeAttempted=true;if(::GetProcessTimes(process,&c,&x,&k,&u)){e.creationTime=(ULONGLONG(c.dwHighDateTime)<<32)|c.dwLowDateTime;e.timeKnown=e.creationTime!=0;}else e.timeError=::GetLastError();e.matched=e.timeKnown&&e.creationTime==expected;if(!e.matched)return {};}
    std::vector<wchar_t> buffer(capacity,L'\0');DWORD chars=capacity;e.queryAttempted=true;const auto ok=::QueryFullProcessImageNameW(process,0,buffer.data(),&chars);e.queryError=ok?0: ::GetLastError();e.returnedChars=chars;
    if(!ok){e.limited=e.queryError==ERROR_INSUFFICIENT_BUFFER;return {};}
    if(!chars||chars>=capacity){e.malformed=true;return {};}e.available=true;e.path.assign(buffer.data(),chars);return e.path;
}
std::wstring QueryEventProcessImagePath(std::uint32_t pid,ProcessImageEvidence* output,ULONGLONG expected){ProcessImageEvidence local;return SampleProcessImage(pid,32768,expected,output?*output:local);}
}
