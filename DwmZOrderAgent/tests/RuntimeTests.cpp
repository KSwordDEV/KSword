#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <vector>
#include "../RuntimeResolver.h"
#include "../RuntimeSignatures.h"

namespace
{
    using namespace ks::dwm_order::runtime;
    unsigned checks = 0, failures = 0;
    void Check(bool condition, const char* label)
    {
        ++checks;
        if (!condition) { ++failures; std::cout << "FAIL=" << label << '\n'; }
    }

    struct Fixture
    {
        std::vector<unsigned char> bytes;
        std::uint32_t ntOffset = 0;
        std::uintptr_t base = 0;
        template<class T> T Read(std::uint32_t at) const
        {
            T value{};
            if (at <= bytes.size() && sizeof(T) <= bytes.size() - at)
                std::memcpy(&value, bytes.data() + at, sizeof(T));
            return value;
        }
        template<class T> void Write(std::uint32_t at, T value)
        { std::memcpy(bytes.data() + at, &value, sizeof(T)); }

        Failure Resolve(Resolved& result, Node* node = nullptr) const
        { return ks::dwm_order::runtime::Resolve(bytes.data(), bytes.size(), base, result, node); }

        bool Load(const wchar_t* path)
        {
            std::ifstream file(std::filesystem::path(path), std::ios::binary | std::ios::ate);
            if (!file || file.tellg() < 0 || file.tellg() > 128 * 1024 * 1024) return false;
            std::vector<unsigned char> raw(static_cast<std::size_t>(file.tellg()));
            file.seekg(0);
            if (!file.read(reinterpret_cast<char*>(raw.data()), static_cast<std::streamsize>(raw.size()))) return false;
            if (raw.size() < sizeof(IMAGE_DOS_HEADER)) return false;
            IMAGE_DOS_HEADER dos{};
            std::memcpy(&dos, raw.data(), sizeof(dos));
            if (dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew < 0 || dos.e_lfanew > 0x1000
                || static_cast<std::size_t>(dos.e_lfanew) + sizeof(IMAGE_NT_HEADERS64) > raw.size()) return false;
            ntOffset = dos.e_lfanew;
            IMAGE_NT_HEADERS64 nt{};
            std::memcpy(&nt, raw.data() + ntOffset, sizeof(nt));
            if (nt.Signature != IMAGE_NT_SIGNATURE || nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC
                || nt.OptionalHeader.SizeOfImage > 128 * 1024 * 1024
                || nt.OptionalHeader.SizeOfHeaders > raw.size()
                || nt.OptionalHeader.SizeOfHeaders > nt.OptionalHeader.SizeOfImage) return false;
            const auto sectionAt = ntOffset + sizeof(nt);
            if (sectionAt + nt.FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER) > raw.size()) return false;
            bytes.resize(nt.OptionalHeader.SizeOfImage);
            std::memcpy(bytes.data(), raw.data(), nt.OptionalHeader.SizeOfHeaders);
            base = nt.OptionalHeader.ImageBase;
            for (unsigned i = 0; i < nt.FileHeader.NumberOfSections; ++i)
            {
                const auto s = Read<IMAGE_SECTION_HEADER>(static_cast<std::uint32_t>(sectionAt + i * sizeof(IMAGE_SECTION_HEADER)));
                if (s.PointerToRawData > raw.size() || s.SizeOfRawData > raw.size() - s.PointerToRawData
                    || s.VirtualAddress > bytes.size() || s.SizeOfRawData > bytes.size() - s.VirtualAddress) return false;
                std::memcpy(bytes.data() + s.VirtualAddress, raw.data() + s.PointerToRawData, s.SizeOfRawData);
            }
            return true;
        }

        std::uint32_t AddSection(std::size_t length, DWORD flags)
        {
            auto nt = Read<IMAGE_NT_HEADERS64>(ntOffset);
            const auto header = ntOffset + static_cast<std::uint32_t>(sizeof(nt)
                + nt.FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER));
            if (header + sizeof(IMAGE_SECTION_HEADER) > nt.OptionalHeader.SizeOfHeaders) return 0;
            const auto rva = static_cast<std::uint32_t>((bytes.size() + 0xfff) & ~std::size_t(0xfff));
            bytes.resize((rva + length + 0xfff) & ~std::size_t(0xfff));
            IMAGE_SECTION_HEADER s{};
            std::memcpy(s.Name, ".fixture", 8);
            s.VirtualAddress = rva;
            s.Misc.VirtualSize = static_cast<DWORD>(length);
            s.Characteristics = flags;
            Write(header, s);
            ++nt.FileHeader.NumberOfSections;
            nt.OptionalHeader.SizeOfImage = static_cast<DWORD>(bytes.size());
            Write(ntOffset, nt);
            return rva;
        }
    };

    const Pattern* Selected(const Fixture& image, const Resolved& result, Node node)
    {
        const auto start = result.functions[static_cast<unsigned>(node)];
        for (const auto& p : signatures::kPatterns)
        {
            if (p.node != node || start + p.length > image.bytes.size()) continue;
            bool match = true;
            for (unsigned i = 0; i < p.length; ++i)
                if ((image.bytes[start + i] & p.mask[i]) != p.bytes[i]) { match = false; break; }
            if (match) return &p;
        }
        return nullptr;
    }

    void Reject(const Fixture& image, Failure expected, const char* name)
    {
        Resolved result{};
        result.model = 99;
        const auto status = image.Resolve(result);
        if (status != expected) std::cout << "REJECTION_STATUS=" << static_cast<unsigned>(status)
            << " EXPECTED=" << static_cast<unsigned>(expected) << '\n';
        Check(status == expected, name);
        Check(result.model == 0 && result.functions[0] == 0 && result.criticalSection == 0,
            "rejected model never publishes partial callable addresses");
    }

    void Regression(const Fixture& image, const Resolved& original)
    {
        auto changed = image;
        auto nt = changed.Read<IMAGE_NT_HEADERS64>(changed.ntOffset);
        nt.FileHeader.TimeDateStamp ^= 0x12345678;
        changed.Write(changed.ntOffset, nt);
        const auto debug = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
        for (unsigned at = 0; at + sizeof(IMAGE_DEBUG_DIRECTORY) <= debug.Size; at += sizeof(IMAGE_DEBUG_DIRECTORY))
        {
            const auto entry = changed.Read<IMAGE_DEBUG_DIRECTORY>(debug.VirtualAddress + at);
            if (entry.Type == IMAGE_DEBUG_TYPE_CODEVIEW && entry.SizeOfData >= 24
                && entry.AddressOfRawData + 24 <= changed.bytes.size()) changed.bytes[entry.AddressOfRawData + 4] ^= 0x55;
        }
        Resolved result{};
        Check(changed.Resolve(result) == Failure::None && result.vtable == original.vtable,
            "timestamp and PDB GUID drift alone does not block an intact ABI model");

        // Simulate ASLR by applying only PE DIR64 relocations; no image execution.
        changed = image;
        const auto reloc = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        const std::uint64_t delta = 0x170000000ull;
        for (unsigned at = 0; at + sizeof(IMAGE_BASE_RELOCATION) <= reloc.Size;)
        {
            const auto block = changed.Read<IMAGE_BASE_RELOCATION>(reloc.VirtualAddress + at);
            if (block.SizeOfBlock < 8 || block.SizeOfBlock > reloc.Size - at) break;
            for (unsigned offset = 8; offset + 2 <= block.SizeOfBlock; offset += 2)
            {
                const auto entry = changed.Read<WORD>(reloc.VirtualAddress + at + offset);
                if ((entry >> 12) == IMAGE_REL_BASED_DIR64)
                {
                    const auto rva = block.VirtualAddress + (entry & 0xfff);
                    changed.Write(rva, changed.Read<std::uint64_t>(rva) + delta);
                }
            }
            at += block.SizeOfBlock;
        }
        changed.base += delta;
        Check(changed.Resolve(result) == Failure::None && result.vtable == original.vtable,
            "relocated absolute vtable and GFIDS pointers resolve at a different load base");

        changed = image;
        changed.bytes[0] = 0;
        Reject(changed, Failure::InvalidImage, "invalid PE rejected");
        changed = image;
        changed.bytes.resize(512);
        Reject(changed, Failure::InvalidImage, "truncated mapped image rejected");
        changed = image;
        auto wrong = nt;
        wrong.FileHeader.Machine = IMAGE_FILE_MACHINE_ARM64;
        changed.Write(changed.ntOffset, wrong);
        Reject(changed, Failure::InvalidImage, "foreign instruction-set model rejected");

        const auto order = original.functions[static_cast<unsigned>(Node::ZOrder)];
        const auto* pattern = Selected(image, original, Node::ZOrder);
        Check(pattern != nullptr, "find the resolved ordering signature for negative fixtures");
        if (!pattern) return;
        changed = image;
        changed.bytes[order] = 0xe9;
        Reject(changed, Failure::MissingPattern, "patched entry rejected");

        constexpr unsigned char splice[] = {0x4c,0x89,0x01,0x48,0x89,0x41,0x08,0x49,0x89,0x48,0x08};
        auto begin = image.bytes.begin() + order;
        auto end = begin + pattern->length;
        auto found = std::search(begin, end, std::begin(splice), std::end(splice));
        Check(found != end, "locate native list direction evidence");
        if (found != end)
        {
            changed = image;
            changed.bytes[static_cast<std::size_t>(found - image.bytes.begin()) + 6] = 0;
            Reject(changed, Failure::MissingPattern, "changed insertion direction rejected");
        }
        constexpr unsigned char desktop[] = {0x48,0x8b,0x92,0x88,0x00,0x00,0x00};
        found = std::search(begin, end, std::begin(desktop), std::end(desktop));
        Check(found != end, "locate layout evidence");
        if (found != end)
        {
            changed = image;
            changed.bytes[static_cast<std::size_t>(found - image.bytes.begin()) + 3] += 8;
            Reject(changed, Failure::MissingPattern, "different CWindowData layout cannot reuse old offsets");
        }
        for (unsigned i = 0; i < pattern->referenceCount; ++i)
        {
            const auto& ref = pattern->references[i];
            if (ref.node == Node::DesktopList)
            {
                changed = image;
                changed.Write(order + ref.displacement, static_cast<std::int32_t>(
                    original.functions[static_cast<unsigned>(Node::FindWindow)] - order - ref.nextInstruction));
                Reject(changed, Failure::ReferenceMismatch, "masked rel32 still requires the correct call graph");
            }
            if (ref.binding == Binding::CriticalSection)
            {
                changed = image;
                changed.Write(order + ref.displacement, changed.Read<std::int32_t>(order + ref.displacement) + 8);
                Reject(changed, Failure::ReferenceMismatch, "lock references must agree across methods");
            }
        }
        changed = image;
        changed.Write(original.vtable + original.zOrderSlot * 8, image.base + original.functions[static_cast<unsigned>(Node::FindWindow)]);
        Reject(changed, Failure::InvalidVtable, "vtable replacement rejected");

        changed = image;
        const auto config = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress;
        const auto cfg = static_cast<std::uint32_t>(changed.Read<std::uint64_t>(config + 128) - image.base);
        const auto count = changed.Read<std::uint64_t>(config + 136);
        const auto stride = 4 + ((changed.Read<std::uint32_t>(config + 144) >> 28) & 15);
        for (unsigned i = 0; i < count; ++i)
            if (changed.Read<std::uint32_t>(cfg + i * stride) == order && stride > 4)
                changed.bytes[cfg + i * stride + 4] |= 1;
        Reject(changed, Failure::InvalidCfg, "CFG-suppressed virtual method rejected");

        // A second exact byte signature at another valid function start must not
        // silently become the selected target, even before call-graph checking.
        changed = image;
        const auto copy = changed.AddSection(pattern->length, IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE);
        const auto exception = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        const auto functions = changed.AddSection(exception.Size + sizeof(RUNTIME_FUNCTION), IMAGE_SCN_MEM_READ);
        Check(copy != 0 && functions != 0, "duplicate fixture has bounded additional sections");
        if (copy && functions)
        {
            std::memcpy(changed.bytes.data() + copy, image.bytes.data() + order, pattern->length);
            std::memcpy(changed.bytes.data() + functions, image.bytes.data() + exception.VirtualAddress, exception.Size);
            RUNTIME_FUNCTION duplicate{copy, copy + pattern->length, 0};
            changed.Write(functions + exception.Size, duplicate);
            auto header = changed.Read<IMAGE_NT_HEADERS64>(changed.ntOffset);
            header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION] = {functions, exception.Size + sizeof(RUNTIME_FUNCTION)};
            changed.Write(changed.ntOffset, header);
            Reject(changed, Failure::AmbiguousPattern, "duplicate executable candidate rejected");
        }
    }
}

int RunRuntimeTests(int argc, wchar_t** argv)
{
    using namespace ks::dwm_order::runtime;
    for (int i = 0; i < argc; ++i)
    {
        Fixture image;
        if (!image.Load(argv[i])) { Check(false, "offline image mapping"); continue; }
        Resolved result{};
        Node node = Node::Count;
        const auto failure = image.Resolve(result, &node);
        std::wcout << L"IMAGE=" << argv[i] << L'\n';
        std::cout << "RESOLVE_FAILURE=" << static_cast<unsigned>(failure) << " NODE=" << static_cast<unsigned>(node)
            << " MODEL=" << result.model << " FIND_RVA=" << std::hex << result.functions[0]
            << " ZORDER_RVA=" << result.functions[2] << " WINDOW_LIST_OFFSET=" << result.windowListOffset << std::dec
            << " HOOK_SLOTS=" << result.destroySlot << ',' << result.zOrderSlot << ',' << result.updateSlot << '\n';
        Check(failure == Failure::None, "reviewed real Windows image resolves without PDB or fixed RVAs");
        if (failure == Failure::None) Regression(image, result);
    }
    std::cout << "RUNTIME_CHECKS=" << checks << " FAILURES=" << failures << '\n';
    return failures ? 1 : 0;
}
