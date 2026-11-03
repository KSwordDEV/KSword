#pragma once

// Read-only, bounded nearest-export lookup from the currently mapped image.
// This is neither a PDB function symbol nor proof of event-time ownership.
#include "ApiMonitorStackSnapshot.h"
#include <algorithm>
#include <cstring>
#include <limits>
#include <string>
#include <vector>

namespace ks::winapi_monitor
{
    struct NearestExportSnapshot {
        bool available = false;
        std::string name;
        std::uint64_t displacement = 0;
        std::uint64_t observedTime100ns = 0;
    };

    namespace export_detail {
        inline constexpr std::size_t kMaximumExportBytes = 2 * 1024 * 1024;
        inline constexpr std::size_t kMaximumNames = 65536;
        inline constexpr std::size_t kMaximumNameLength = 256;
        inline constexpr std::size_t kMaximumNameBytesScanned = 2 * 1024 * 1024;
        inline constexpr std::uint32_t kMaximumDisplacement = 1024 * 1024;
        inline bool range(std::size_t offset, std::size_t length, std::size_t limit) noexcept
        { return offset <= limit && length <= limit - offset; }
        template<class T> bool item(const std::vector<std::uint8_t>& bytes, std::size_t at, T& out) noexcept
        {
            if (!range(at, sizeof(T), bytes.size())) return false;
            std::memcpy(&out, bytes.data() + at, sizeof(T)); return true;
        }
        inline bool table(std::uint32_t rva, std::size_t count, std::size_t width,
                          std::uint32_t base, std::size_t size) noexcept
        {
            if (rva < base || count > size / width) return false;
            return range(static_cast<std::size_t>(rva - base), count * width, size);
        }
        // blob contains exactly the image's export directory and its arrays.
        // Section range is an already validated executable section in the image.
        inline NearestExportSnapshot find(const std::vector<std::uint8_t>& blob, std::uint32_t directoryRva,
            std::uint32_t imageSize, std::uint32_t sectionStart, std::uint32_t sectionEnd, std::uint32_t targetRva)
        {
            NearestExportSnapshot result;
            IMAGE_EXPORT_DIRECTORY dir{};
            if (blob.size() < sizeof(dir) || blob.size() > kMaximumExportBytes || !item(blob, 0, dir)
                || !dir.NumberOfNames || dir.NumberOfNames > kMaximumNames || !dir.NumberOfFunctions
                || dir.NumberOfFunctions > kMaximumNames || targetRva >= imageSize
                || sectionStart >= sectionEnd || sectionEnd > imageSize
                || targetRva < sectionStart || targetRva >= sectionEnd
                || !table(dir.AddressOfNames, dir.NumberOfNames, sizeof(DWORD), directoryRva, blob.size())
                || !table(dir.AddressOfNameOrdinals, dir.NumberOfNames, sizeof(WORD), directoryRva, blob.size())
                || !table(dir.AddressOfFunctions, dir.NumberOfFunctions, sizeof(DWORD), directoryRva, blob.size())) return result;
            std::uint32_t best = 0;
            std::size_t scannedNameBytes = 0;
            for (std::size_t i = 0; i < dir.NumberOfNames; ++i) {
                DWORD nameRva = 0, functionRva = 0; WORD ordinal = 0;
                if (!item(blob, dir.AddressOfNames - directoryRva + i * sizeof(DWORD), nameRva)
                    || !item(blob, dir.AddressOfNameOrdinals - directoryRva + i * sizeof(WORD), ordinal)
                    || ordinal >= dir.NumberOfFunctions
                    || !item(blob, dir.AddressOfFunctions - directoryRva + std::size_t(ordinal) * sizeof(DWORD), functionRva)) return {};
                // Forwarders point back inside the export directory and are not executable addresses.
                if (functionRva >= directoryRva && std::uint64_t(functionRva) - directoryRva < blob.size()) continue;
                if (functionRva < sectionStart || functionRva >= sectionEnd || functionRva > targetRva
                    || targetRva - functionRva > kMaximumDisplacement || (result.available && functionRva <= best)) continue;
                if (nameRva < directoryRva || std::size_t(nameRva - directoryRva) >= blob.size()) return {};
                const auto at = std::size_t(nameRva - directoryRva);
                std::size_t length = 0;
                while (length < kMaximumNameLength && range(at, length + 1, blob.size()) && blob[at + length]) {
                    if (++scannedNameBytes > kMaximumNameBytesScanned) return {};
                    const auto c = blob[at + length];
                    if (c < 0x21 || c > 0x7e) return {};
                    ++length;
                }
                if (!length || length == kMaximumNameLength || !range(at, length + 1, blob.size())) return {};
                result.name.assign(reinterpret_cast<const char*>(blob.data() + at), length);
                result.available = true; best = functionRva;
            }
            if (result.available) result.displacement = targetRva - best;
            return result;
        }
        struct Handle { HANDLE value = nullptr; ~Handle() { if (value) ::CloseHandle(value); } };
        inline bool read(HANDLE process, std::uint64_t base, std::uint64_t offset, void* out, std::size_t size)
        {
            if (!size || size > kMaximumExportBytes || base > UINTPTR_MAX || offset > UINTPTR_MAX - base
                || size > UINTPTR_MAX - (base + offset)) return false;
            // Every byte read must still be committed in the same image mapping.
            std::uint64_t cursor = base + offset, remaining = size;
            for (std::size_t queries = 0; remaining; ++queries) {
                if (queries >= 512) return false;
                MEMORY_BASIC_INFORMATION region{};
                if (::VirtualQueryEx(process, reinterpret_cast<LPCVOID>(static_cast<std::uintptr_t>(cursor)), &region, sizeof(region)) != sizeof(region)
                    || region.State != MEM_COMMIT || region.Type != MEM_IMAGE
                    || reinterpret_cast<std::uintptr_t>(region.AllocationBase) != base) return false;
                const auto regionBase = reinterpret_cast<std::uintptr_t>(region.BaseAddress);
                if (cursor < regionBase || cursor - regionBase >= region.RegionSize) return false;
                const auto available = region.RegionSize - (cursor - regionBase);
                const auto advance = (std::min)(remaining, static_cast<std::uint64_t>(available));
                if (!advance) return false;
                cursor += advance; remaining -= advance;
            }
            SIZE_T got = 0;
            return ::ReadProcessMemory(process, reinterpret_cast<LPCVOID>(static_cast<std::uintptr_t>(base + offset)), out, size, &got) && got == size;
        }
        inline bool liveIdentity(HANDLE process, std::uint64_t expected)
        {
            FILETIME created{}, exited{}, kernel{}, user{};
            return ::WaitForSingleObject(process, 0) == WAIT_TIMEOUT
                && ::GetProcessTimes(process, &created, &exited, &kernel, &user)
                && ((std::uint64_t(created.dwHighDateTime) << 32) | created.dwLowDateTime) == expected;
        }
        inline bool sameMapping(HANDLE process, const StackFrameSnapshot& frame, std::uint64_t base)
        {
            MEMORY_BASIC_INFORMATION info{};
            if (::VirtualQueryEx(process, reinterpret_cast<LPCVOID>(static_cast<std::uintptr_t>(frame.address)), &info, sizeof(info)) != sizeof(info)
                || info.State != MEM_COMMIT || info.Type != MEM_IMAGE
                || reinterpret_cast<std::uintptr_t>(info.AllocationBase) != base) return false;
            using MappedFile = DWORD (WINAPI*)(HANDLE, LPVOID, LPWSTR, DWORD);
            const auto kernel = ::GetModuleHandleW(L"kernel32.dll");
            const auto fn = kernel ? std::bit_cast<MappedFile>(::GetProcAddress(kernel, "K32GetMappedFileNameW")) : nullptr;
            wchar_t path[4096]{};
            const auto length = fn ? fn(process, info.BaseAddress, path, static_cast<DWORD>(std::size(path))) : 0;
            return length && length < std::size(path) - 1 && frame.mappedPath.size() == length
                && ::_wcsnicmp(path, frame.mappedPath.c_str(), length) == 0;
        }
    }

    inline NearestExportSnapshot QueryNearestExport(std::uint32_t pid, std::uint64_t creation,
                                                     const StackFrameSnapshot& frame)
    {
        using namespace export_detail;
        if (!pid || !creation || !frame.imageOffsetAvailable || frame.mappedPath.empty()
            || frame.address > UINTPTR_MAX || frame.imageOffset > frame.address
            || frame.imageOffset > UINT32_MAX) return {};
        const std::uint64_t base = frame.address - frame.imageOffset;
        Handle process{::OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | SYNCHRONIZE, FALSE, pid)};
        if (!process.value || !liveIdentity(process.value, creation) || !sameMapping(process.value, frame, base)) return {};
        IMAGE_DOS_HEADER dos{};
        if (!read(process.value, base, 0, &dos, sizeof(dos)) || dos.e_magic != IMAGE_DOS_SIGNATURE
            || dos.e_lfanew < static_cast<LONG>(sizeof(dos)) || dos.e_lfanew > 1024 * 1024) return {};
        const auto nt = static_cast<std::uint32_t>(dos.e_lfanew);
        DWORD signature = 0; IMAGE_FILE_HEADER file{};
        if (!read(process.value, base, nt, &signature, sizeof(signature)) || signature != IMAGE_NT_SIGNATURE
            || !read(process.value, base, nt + sizeof(signature), &file, sizeof(file))
            || !file.NumberOfSections || file.NumberOfSections > 96) return {};
        const std::uint64_t optOffset = std::uint64_t(nt) + sizeof(signature) + sizeof(file);
        WORD magic = 0;
        if (!read(process.value, base, optOffset, &magic, sizeof(magic))) return {};
        std::uint32_t imageSize = 0; IMAGE_DATA_DIRECTORY exports{};
        if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
            IMAGE_OPTIONAL_HEADER64 opt{};
            if (file.SizeOfOptionalHeader < sizeof(opt) || !read(process.value, base, optOffset, &opt, sizeof(opt))
                || !opt.NumberOfRvaAndSizes) return {};
            imageSize = opt.SizeOfImage; exports = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        } else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
            IMAGE_OPTIONAL_HEADER32 opt{};
            if (file.SizeOfOptionalHeader < sizeof(opt) || !read(process.value, base, optOffset, &opt, sizeof(opt))
                || !opt.NumberOfRvaAndSizes) return {};
            imageSize = opt.SizeOfImage; exports = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        } else return {};
        const auto sectionOffset = optOffset + file.SizeOfOptionalHeader;
        const auto sectionBytes = std::size_t(file.NumberOfSections) * sizeof(IMAGE_SECTION_HEADER);
        if (!imageSize || !range(sectionOffset, sectionBytes, imageSize)
            || !range(exports.VirtualAddress, exports.Size, imageSize)
            || exports.Size < sizeof(IMAGE_EXPORT_DIRECTORY) || exports.Size > kMaximumExportBytes
            || frame.imageOffset >= imageSize) return {};
        std::vector<IMAGE_SECTION_HEADER> sections(file.NumberOfSections);
        if (!read(process.value, base, sectionOffset, sections.data(), sectionBytes)) return {};
        std::uint32_t first = 0, last = 0;
        for (const auto& section : sections) {
            const auto size = (std::max)(section.Misc.VirtualSize, section.SizeOfRawData);
            if (!(section.Characteristics & IMAGE_SCN_MEM_EXECUTE) || !size
                || !range(section.VirtualAddress, size, imageSize)) continue;
            if (frame.imageOffset >= section.VirtualAddress && frame.imageOffset - section.VirtualAddress < size) {
                if (last) return {}; // Reject ambiguous overlapping executable sections.
                first = section.VirtualAddress; last = first + size;
            }
        }
        if (!last) return {};
        std::vector<std::uint8_t> blob(exports.Size);
        if (!read(process.value, base, exports.VirtualAddress, blob.data(), blob.size())) return {};
        auto result = find(blob, exports.VirtualAddress, imageSize, first, last, static_cast<std::uint32_t>(frame.imageOffset));
        if (!liveIdentity(process.value, creation) || !sameMapping(process.value, frame, base)) return {};
        if (result.available) {
            FILETIME observed{}; ::GetSystemTimeAsFileTime(&observed);
            result.observedTime100ns = (std::uint64_t(observed.dwHighDateTime) << 32) | observed.dwLowDateTime;
        }
        return result;
    }
}
