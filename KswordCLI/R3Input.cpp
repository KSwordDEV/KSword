#include "CommandRegistry.h"
#include <Windows.h>
#include <cwctype>
#include <stdexcept>
namespace ks::cli {
Payload readPayloadFile(const std::wstring& path) {
    Payload result;
    const auto file=CreateFileW(path.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);
    if(file==INVALID_HANDLE_VALUE) {result.win32Error=GetLastError();return result;}
    struct FileOwner {HANDLE value;~FileOwner(){CloseHandle(value);}} owner{file};
    LARGE_INTEGER size{};
    if(!GetFileSizeEx(file,&size)) result.win32Error=GetLastError();
    else if(size.QuadPart<0 || size.QuadPart>64*1024*1024) result.win32Error=ERROR_FILE_TOO_LARGE;
    else {
        result.bytes.resize(static_cast<std::size_t>(size.QuadPart));
        DWORD offset=0;
        while(offset<result.bytes.size()) {
            DWORD count=0;
            if(!ReadFile(file,result.bytes.data()+offset,static_cast<DWORD>(result.bytes.size()-offset),&count,nullptr)) {result.win32Error=GetLastError();break;}
            if(count==0) {result.win32Error=ERROR_HANDLE_EOF;break;}
            offset+=count;
        }
    }
    if(result.win32Error) result.bytes.clear();
    return result;
}
std::vector<std::uint8_t> parseHexPayload(const std::wstring& text) {
    std::wstring clean;
    std::size_t start=text.starts_with(L"0x") || text.starts_with(L"0X") ? 2 : 0;
    for(std::size_t i=start;i<text.size();++i) {
        const auto c=text[i];
        if(std::iswspace(c)) continue;
        if(!((c>=L'0' && c<=L'9') || (c>=L'a' && c<=L'f') || (c>=L'A' && c<=L'F'))) throw std::invalid_argument("invalid hex payload");
        clean+=c;
    }
    if(clean.size()%2) throw std::invalid_argument("hex payload must contain whole bytes");
    std::vector<std::uint8_t> bytes;
    for(std::size_t i=0;i<clean.size();i+=2) bytes.push_back(static_cast<std::uint8_t>(std::stoul(clean.substr(i,2),nullptr,16)));
    return bytes;
}
}
