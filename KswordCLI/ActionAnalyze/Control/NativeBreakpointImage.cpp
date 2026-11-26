#ifndef NOMINMAX
#define NOMINMAX
#endif
#include "NativeBreakpointImage.h"

#include <TlHelp32.h>

#include <limits>
#include <vector>

namespace ks::cli::action_analyze::control {
namespace {

struct ImageReader {
    HANDLE process;
    std::uintptr_t base;
    std::uint32_t size;

    bool Contains(std::uint32_t rva, std::size_t count) const {
        return rva < size && count <= size - rva;
    }

    bool Read(std::uint32_t rva, void* data, std::size_t count) const {
        SIZE_T got = 0;
        return Contains(rva, count) && ReadProcessMemory(process, reinterpret_cast<void*>(base + rva),
            data, count, &got) && got == count;
    }

    template<class T> bool Read(std::uint32_t rva, T& value) const {
        return Read(rva, &value, sizeof(value));
    }
};

DWORD GetImage(DWORD pid, std::wstring_view path, std::uintptr_t& base, DWORD& size) {
    const HANDLE modules = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
    if (modules == INVALID_HANDLE_VALUE) { return GetLastError(); }
    MODULEENTRY32W module{};
    module.dwSize = sizeof(module);
    DWORD error = ERROR_SUCCESS;
    if (!Module32FirstW(modules, &module)) {
        error = GetLastError();
    } else {
        do {
            if (CompareStringOrdinal(module.szExePath, -1, path.data(), static_cast<int>(path.size()), TRUE) != CSTR_EQUAL) {
                continue;
            }
            if (base) { error = ERROR_DUP_NAME; break; }
            base = reinterpret_cast<std::uintptr_t>(module.modBaseAddr);
            size = module.modBaseSize;
        } while (Module32NextW(modules, &module));
        if (!error && GetLastError() != ERROR_NO_MORE_FILES) { error = GetLastError(); }
    }
    CloseHandle(modules);
    return error ? error : base ? ERROR_SUCCESS : ERROR_MOD_NOT_FOUND;
}

DWORD ReadExport(const ImageReader& image, IMAGE_DATA_DIRECTORY entry, std::string_view wanted, DWORD& rva) {
    IMAGE_EXPORT_DIRECTORY exports{};
    constexpr DWORD kMaxExports = 65536;
    if (entry.Size < sizeof(exports) || !image.Contains(entry.VirtualAddress, entry.Size) ||
        !image.Read(entry.VirtualAddress, exports) || exports.NumberOfNames > kMaxExports ||
        exports.NumberOfFunctions > kMaxExports || exports.NumberOfNames > exports.NumberOfFunctions) {
        return ERROR_BAD_EXE_FORMAT;
    }
    if (!exports.NumberOfNames) { return ERROR_PROC_NOT_FOUND; }
    std::vector<DWORD> names(exports.NumberOfNames);
    std::vector<WORD> ordinals(exports.NumberOfNames);
    if (!image.Read(exports.AddressOfNames, names.data(), names.size() * sizeof(names[0])) ||
        !image.Read(exports.AddressOfNameOrdinals, ordinals.data(), ordinals.size() * sizeof(ordinals[0])) ||
        !image.Contains(exports.AddressOfFunctions, exports.NumberOfFunctions * sizeof(DWORD))) {
        return ERROR_BAD_EXE_FORMAT;
    }
    // PE 名称表按字典序排序；按需读取，禁止扫描全导出表或无界读取字符串。
    std::size_t lo = 0;
    std::size_t hi = names.size();
    while (lo < hi) {
        const auto mid = lo + (hi - lo) / 2;
        int cmp = 0;
        for (std::size_t i = 0; i <= wanted.size(); ++i) {
            char byte = 0;
            if (names[mid] >= image.size || i >= image.size - names[mid] ||
                !image.Read(names[mid] + static_cast<DWORD>(i), byte)) { return ERROR_BAD_EXE_FORMAT; }
            const char expected = i == wanted.size() ? '\0' : wanted[i];
            cmp = static_cast<unsigned char>(byte) - static_cast<unsigned char>(expected);
            if (cmp || !byte) { break; }
        }
        if (cmp < 0) { lo = mid + 1; continue; }
        if (cmp > 0) { hi = mid; continue; }
        if (ordinals[mid] >= exports.NumberOfFunctions ||
            !image.Read(exports.AddressOfFunctions + ordinals[mid] * static_cast<DWORD>(sizeof(DWORD)), rva) || !rva) {
            return ERROR_BAD_EXE_FORMAT;
        }
        if (rva >= entry.VirtualAddress && rva - entry.VirtualAddress < entry.Size) { return ERROR_NOT_SUPPORTED; }
        return ERROR_SUCCESS;
    }
    return ERROR_PROC_NOT_FOUND;
}

} // namespace

DWORD ResolveNativeImageSite(HANDLE process, DWORD pid, std::wstring_view path,
    std::optional<std::uint32_t> rva, std::string_view exportName, NativeImageSite& site, std::uint32_t dataBytes) {
    std::uintptr_t base = 0;
    DWORD size = 0;
    if (const auto error = GetImage(pid, path, base, size)) { return error; }
    if (size > std::numeric_limits<std::uintptr_t>::max() - base) { return ERROR_BAD_EXE_FORMAT; }
    const ImageReader image{process, base, size};
    IMAGE_DOS_HEADER dos{};
    IMAGE_NT_HEADERS64 pe{};
    if (!image.Read(0, dos) || dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew < static_cast<LONG>(sizeof(dos)) ||
        !image.Read(static_cast<DWORD>(dos.e_lfanew), pe) || pe.Signature != IMAGE_NT_SIGNATURE ||
        pe.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 || pe.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
        pe.FileHeader.SizeOfOptionalHeader != sizeof(IMAGE_OPTIONAL_HEADER64) || pe.OptionalHeader.SizeOfImage != size ||
        !pe.FileHeader.NumberOfSections || pe.FileHeader.NumberOfSections > 96) { return ERROR_BAD_EXE_FORMAT; }
    const DWORD sectionTable = static_cast<DWORD>(dos.e_lfanew) + static_cast<DWORD>(sizeof(pe));
    if (!image.Contains(sectionTable, pe.FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER))) {
        return ERROR_BAD_EXE_FORMAT;
    }
    DWORD addressRva = rva.value_or(0);
    if (!rva) {
        if (pe.OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXPORT) { return ERROR_PROC_NOT_FOUND; }
        const auto directory = pe.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (!directory.VirtualAddress) { return ERROR_PROC_NOT_FOUND; }
        if (const auto error = ReadExport(image, directory, exportName, addressRva)) { return error; }
    }
    const auto width = dataBytes ? dataBytes : 1; // 数据关注点必须完整位于一个数据节。
    if (!image.Contains(addressRva, width)) { return ERROR_INVALID_ADDRESS; }
    bool eligibleSection = false; // 根据关注点用途区分只执行位置与可写数据。
    for (WORD i = 0; i < pe.FileHeader.NumberOfSections; ++i) {
        IMAGE_SECTION_HEADER section{};
        if (!image.Read(sectionTable + i * static_cast<DWORD>(sizeof(section)), section)) { return ERROR_BAD_EXE_FORMAT; }
        if (addressRva >= section.VirtualAddress && width <= section.Misc.VirtualSize &&
            addressRva - section.VirtualAddress <= section.Misc.VirtualSize - width) {
            const bool executable = (section.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0; // PE 节属性。
            eligibleSection = dataBytes ? !executable && (section.Characteristics & IMAGE_SCN_MEM_WRITE) != 0 : executable;
            break;
        }
    }
    MEMORY_BASIC_INFORMATION memory{};
    const auto address = base + addressRva;
    // 同一地址还必须被当前进程映射为对应的内存类型。
    const DWORD eligibleProtection = dataBytes ? PAGE_READWRITE | PAGE_WRITECOPY :
        PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    if (!eligibleSection || (dataBytes && address % dataBytes) ||
        !VirtualQueryEx(process, reinterpret_cast<void*>(address), &memory, sizeof(memory)) ||
        reinterpret_cast<std::uintptr_t>(memory.AllocationBase) != base || memory.Type != MEM_IMAGE ||
        memory.State != MEM_COMMIT || (memory.Protect & PAGE_GUARD) ||
        !(memory.Protect & eligibleProtection) || memory.RegionSize < width ||
        address - reinterpret_cast<std::uintptr_t>(memory.BaseAddress) > memory.RegionSize - width) {
        return ERROR_INVALID_ADDRESS;
    }
    site = {base, address, addressRva};
    return ERROR_SUCCESS;
}

} // namespace ks::cli::action_analyze::control
