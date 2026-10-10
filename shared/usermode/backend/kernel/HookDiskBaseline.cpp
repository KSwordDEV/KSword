#include "HookDiskBaseline.h"
#include <algorithm>
#include <cstring>
#include <cwctype>
#include <iomanip>
#include <sstream>
#pragma comment(lib,"Psapi.lib")
namespace ks::r3::kernel::disk {
std::wstring NormalizeKernelModulePath(const std::wstring& path) {
    std::wstring result = path;
    constexpr wchar_t ntPrefix[] = L"\\??\\";
    if (_wcsnicmp(result.c_str(), ntPrefix, 4) == 0) {
        result.erase(0, 4);
    }
    constexpr wchar_t systemRootPrefix[] = L"\\SystemRoot\\";
    if (_wcsnicmp(result.c_str(), systemRootPrefix, 12) == 0) {
        wchar_t windowsDir[MAX_PATH]{};
        if (::GetWindowsDirectoryW(windowsDir, MAX_PATH) != 0) {
            result = std::wstring(windowsDir) + result.substr(11);
        }
    }
    constexpr wchar_t sysrootPrefix[] = L"SystemRoot\\";
    if (_wcsnicmp(result.c_str(), sysrootPrefix, 11) == 0) {
        wchar_t windowsDir[MAX_PATH]{};
        if (::GetWindowsDirectoryW(windowsDir, MAX_PATH) != 0) {
            result = std::wstring(windowsDir) + L"\\" + result.substr(11);
        }
    }
    return result;
}
std::unordered_map<std::uint64_t, KernelModuleDiskInfo> QueryLoadedKernelModuleMap() {
    std::unordered_map<std::uint64_t, KernelModuleDiskInfo> modules;
    DWORD bytesNeeded = 0;
    ::EnumDeviceDrivers(nullptr, 0, &bytesNeeded);
    if (bytesNeeded == 0) {
        return modules;
    }
    std::vector<LPVOID> bases(bytesNeeded / sizeof(LPVOID));
    if (!::EnumDeviceDrivers(bases.data(), bytesNeeded, &bytesNeeded)) {
        return modules;
    }
    const DWORD count = bytesNeeded / sizeof(LPVOID);
    for (DWORD index = 0; index < count; ++index) {
        wchar_t path[MAX_PATH * 4]{};
        if (!::GetDeviceDriverFileNameW(bases[index], path, static_cast<DWORD>(std::size(path)))) {
            continue;
        }
        KernelModuleDiskInfo info;
        info.base = reinterpret_cast<std::uint64_t>(bases[index]);
        info.ntPath = path;
        info.win32Path = NormalizeKernelModulePath(info.ntPath);
        modules[info.base] = std::move(info);
    }
    return modules;
}
bool ReadWholeBinaryFile(const std::wstring& path,std::vector<std::uint8_t>& bytesOut,DiskReadEvidence* evidenceOut){
    DiskReadEvidence local;auto& e=evidenceOut?*evidenceOut:local;e={};bool complete=false;
    [&]{HANDLE file=::CreateFileW(path.c_str(),GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);
        if(file==INVALID_HANDLE_VALUE){e.error=::GetLastError();return;}
        struct Owner{HANDLE handle;DiskReadEvidence& e;~Owner(){e.closeAttempted=true;::SetLastError(0);e.closed=::CloseHandle(handle)!=FALSE;e.closeError=e.closed?0: ::GetLastError();}} owner{file,e};e.opened=true;
        LARGE_INTEGER size{};if(!::GetFileSizeEx(file,&size)){e.error=::GetLastError();return;}if(size.QuadPart<0){e.error=ERROR_BAD_EXE_FORMAT;return;}e.sizeKnown=true;e.size=static_cast<std::uint64_t>(size.QuadPart);
        if(size.QuadPart==0){e.error=ERROR_BAD_EXE_FORMAT;return;}if(size.QuadPart>128LL*1024LL*1024LL){e.limited=true;return;}
        e.identityKnown=::GetFileInformationByHandle(file,&e.identity)!=FALSE;e.identityError=e.identityKnown?0: ::GetLastError();
        std::vector<std::uint8_t> bytes(static_cast<std::size_t>(size.QuadPart));DWORD read=0;const auto ok=::ReadFile(file,bytes.data(),static_cast<DWORD>(bytes.size()),&read,nullptr);e.bytesRead=read;
        if(!ok||read!=bytes.size()){e.error=ok?ERROR_HANDLE_EOF: ::GetLastError();return;}
        BY_HANDLE_FILE_INFORMATION after{};if(!::GetFileInformationByHandle(file,&after)){e.identityKnown=false;e.identityError=::GetLastError();}
        else if(e.identityKnown)e.identityChanged=e.identity.dwVolumeSerialNumber!=after.dwVolumeSerialNumber||e.identity.nFileIndexHigh!=after.nFileIndexHigh||e.identity.nFileIndexLow!=after.nFileIndexLow||e.identity.nFileSizeHigh!=after.nFileSizeHigh||e.identity.nFileSizeLow!=after.nFileSizeLow||e.identity.ftLastWriteTime.dwHighDateTime!=after.ftLastWriteTime.dwHighDateTime||e.identity.ftLastWriteTime.dwLowDateTime!=after.ftLastWriteTime.dwLowDateTime;
        bytesOut=std::move(bytes);e.complete=true;complete=true;
    }();return complete;
}
bool RvaToFileOffset(const std::vector<std::uint8_t>& bytes,std::uint32_t rva,std::uint32_t count,std::uint64_t& offsetOut,RvaEvidence* evidenceOut){
    RvaEvidence local;auto& e=evidenceOut?*evidenceOut:local;e={};const auto fits=[&](std::uint64_t offset,std::uint64_t size){return offset<=bytes.size()&&size<=bytes.size()-offset;};
    IMAGE_DOS_HEADER dos{};if(!fits(0,sizeof(dos))){e.malformed=true;return false;}memcpy(&dos,bytes.data(),sizeof(dos));
    if(dos.e_magic!=IMAGE_DOS_SIGNATURE||dos.e_lfanew<=0){e.malformed=true;return false;}
    const auto nt=static_cast<std::uint64_t>(dos.e_lfanew);if(!fits(nt,sizeof(DWORD)+sizeof(IMAGE_FILE_HEADER))){e.malformed=true;return false;}
    DWORD signature=0;IMAGE_FILE_HEADER header{};memcpy(&signature,bytes.data()+nt,4);memcpy(&header,bytes.data()+nt+4,sizeof(header));
    const auto optional=nt+4+sizeof(header);if(signature!=IMAGE_NT_SIGNATURE||!header.NumberOfSections||header.NumberOfSections>96||!fits(optional,header.SizeOfOptionalHeader)||header.SizeOfOptionalHeader<64){e.malformed=true;return false;}
    memcpy(&e.optionalMagic,bytes.data()+optional,2);if((e.optionalMagic!=IMAGE_NT_OPTIONAL_HDR32_MAGIC&&e.optionalMagic!=IMAGE_NT_OPTIONAL_HDR64_MAGIC)||header.SizeOfOptionalHeader<(e.optionalMagic==IMAGE_NT_OPTIONAL_HDR32_MAGIC?sizeof(IMAGE_OPTIONAL_HEADER32):sizeof(IMAGE_OPTIONAL_HEADER64))){e.malformed=true;return false;}
    DWORD sizeOfHeaders=0;memcpy(&sizeOfHeaders,bytes.data()+optional+60,4);const auto sections=optional+header.SizeOfOptionalHeader;
    if(!fits(sections,std::uint64_t(header.NumberOfSections)*sizeof(IMAGE_SECTION_HEADER))||sizeOfHeaders<sections+std::uint64_t(header.NumberOfSections)*sizeof(IMAGE_SECTION_HEADER)||sizeOfHeaders>bytes.size()){e.malformed=true;return false;}
    const auto end=std::uint64_t(rva)+count;bool mapped=count&&end<=sizeOfHeaders&&fits(rva,count);std::uint64_t offset=mapped?rva:0;UINT overlapping=mapped?1:0;
    for(WORD index=0;index<header.NumberOfSections;++index){IMAGE_SECTION_HEADER section{};memcpy(&section,bytes.data()+sections+std::uint64_t(index)*sizeof(section),sizeof(section));
        const auto mappedSize=(std::max)(section.Misc.VirtualSize,section.SizeOfRawData);const auto sectionEnd=std::uint64_t(section.VirtualAddress)+mappedSize;
        if(sectionEnd>0x100000000ULL||(section.SizeOfRawData&&!fits(section.PointerToRawData,section.SizeOfRawData))){e.malformed=true;return false;}
        if(!count||rva<section.VirtualAddress||rva>=sectionEnd)continue;if(++overlapping>1){e.malformed=true;return false;}
        const auto delta=std::uint64_t(rva)-section.VirtualAddress;if(delta+count>section.SizeOfRawData)continue;
        const auto candidate=std::uint64_t(section.PointerToRawData)+delta;if(!fits(candidate,count)){e.malformed=true;return false;}mapped=true;offset=candidate;
    }
    e.validPe=true;if(end>0x100000000ULL)return false;e.mapped=mapped;if(mapped)offsetOut=offset;return mapped;
}
InlineDiskBaseline ReadInlineDiskBaseline(
    const ksword::ark::KernelInlineHookEntry& entry,
    const std::unordered_map<std::uint64_t, KernelModuleDiskInfo>& modules,
    std::unordered_map<std::wstring, std::vector<std::uint8_t>>& fileCache) {
    InlineDiskBaseline baseline;
    const std::uint32_t byteCount = static_cast<std::uint32_t>(std::min<std::size_t>(
        std::min<std::size_t>(entry.currentBytes.size(), entry.currentByteCount),
        KSWORD_ARK_KERNEL_HOOK_BYTES));
    baseline.byteCount = byteCount;
    if (byteCount == 0) {
        baseline.statusText = L"不可用：R0 未返回内存字节。";
        return baseline;
    }
    if (entry.moduleBase == 0 || entry.functionAddress < entry.moduleBase) {
        baseline.statusText = L"不可用：函数地址或模块基址无效。";
        return baseline;
    }
    const std::uint64_t rva64 = entry.functionAddress - entry.moduleBase;
    baseline.rva = rva64;
    if (rva64 > 0xFFFFFFFFULL) {
        baseline.statusText = L"不可用：函数 RVA 超出 32 位 PE 范围。";
        return baseline;
    }
    const auto module = modules.find(entry.moduleBase);
    if (module == modules.end()) {
        baseline.statusText = L"不可用：R3 未能反查模块磁盘路径。";
        return baseline;
    }
    baseline.filePath = module->second.win32Path;
    if (baseline.filePath.empty() || ::GetFileAttributesW(baseline.filePath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        baseline.statusText = L"不可用：磁盘模块文件不存在或路径不可转换（" + module->second.ntPath + L"）。";
        return baseline;
    }
    auto cache = fileCache.find(baseline.filePath);
    if (cache == fileCache.end()) {
        std::vector<std::uint8_t> fileBytes;
        if (!ReadWholeBinaryFile(baseline.filePath, fileBytes)) {
            baseline.statusText = L"不可用：磁盘模块文件读取失败。";
            return baseline;
        }
        cache = fileCache.emplace(baseline.filePath, std::move(fileBytes)).first;
    }
    std::uint64_t fileOffset = 0;
    if (!RvaToFileOffset(cache->second, static_cast<std::uint32_t>(rva64), byteCount, fileOffset)) {
        baseline.statusText = L"不可用：未找到覆盖目标 RVA 的 PE 区段。";
        return baseline;
    }
    baseline.bytes.assign(cache->second.begin() + static_cast<std::ptrdiff_t>(fileOffset),
        cache->second.begin() + static_cast<std::ptrdiff_t>(fileOffset + byteCount));
    baseline.available = true;
    baseline.differs = !std::equal(baseline.bytes.begin(), baseline.bytes.end(), entry.currentBytes.begin());
    baseline.statusText = baseline.differs ? L"不同：内存字节与磁盘基线不一致" : L"一致：内存字节与磁盘基线相同";
    return baseline;
}
}
