#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include <algorithm>
#include <cstring>
#include "RuntimeResolver.h"
#include "RuntimeSignatures.h"
#include "RuntimeWin10Signatures.h"

namespace ks::dwm_order::runtime
{
    namespace
    {
        constexpr unsigned kNodes = static_cast<unsigned>(Node::Count);
        constexpr unsigned kMaxFragments = 64;
        struct Model
        {
            std::uint32_t id;
            Layout layout;
            const Pattern* patterns;
            std::size_t patternCount;
            bool fragmented;
        };
        const Model kModels[] = {
            {1, signatures::kLayout, signatures::kPatterns, std::size(signatures::kPatterns), false},
            {2, win10_signatures::kLayout, win10_signatures::kPatterns, std::size(win10_signatures::kPatterns), true}
        };

        bool Accessible(const void* memory, std::size_t bytes)
        {
            auto address = reinterpret_cast<std::uintptr_t>(memory);
            if (!address || bytes > UINTPTR_MAX - address) return false;
            const auto end = address + bytes;
            while (address < end)
            {
                MEMORY_BASIC_INFORMATION info{};
                if (!VirtualQuery(reinterpret_cast<const void*>(address), &info, sizeof(info))
                    || info.State != MEM_COMMIT || (info.Protect & (PAGE_GUARD | PAGE_NOACCESS))) return false;
                const auto next = reinterpret_cast<std::uintptr_t>(info.BaseAddress) + info.RegionSize;
                if (next <= address) return false;
                address = next;
            }
            return true;
        }

        struct Image
        {
            const unsigned char* data;
            std::size_t bytes;
            std::uintptr_t base;
            IMAGE_NT_HEADERS64 nt{};
            IMAGE_SECTION_HEADER sections[96]{};
            bool available[96]{};
            const RUNTIME_FUNCTION* functions = nullptr;
            std::uint32_t functionCount = 0;

            bool Range(std::uint64_t rva, std::uint64_t count) const
            { return rva <= bytes && count <= bytes - rva; }

            template<class T> T Read(std::uint32_t rva) const
            {
                T value{};
                if (Range(rva, sizeof(T))) std::memcpy(&value, data + rva, sizeof(T));
                return value;
            }

            bool In(std::uint32_t rva, std::size_t count, Section kind) const
            {
                if (!Range(rva, count)) return false;
                for (unsigned i = 0; i < nt.FileHeader.NumberOfSections; ++i)
                {
                    const auto& s = sections[i];
                    const auto size = s.Misc.VirtualSize;
                    if (!available[i] || rva < s.VirtualAddress || rva - s.VirtualAddress > size
                        || count > size - (rva - s.VirtualAddress)) continue;
                    const auto actual = (s.Characteristics & IMAGE_SCN_MEM_EXECUTE) ? Section::Code
                        : (s.Characteristics & IMAGE_SCN_MEM_WRITE) ? Section::Writable : Section::ReadOnly;
                    return kind == actual;
                }
                return false;
            }

            bool Open()
            {
                if (!data || bytes < sizeof(IMAGE_DOS_HEADER) || bytes > 128 * 1024 * 1024
                    || !Accessible(data, sizeof(IMAGE_DOS_HEADER))) return false;
                const auto dos = Read<IMAGE_DOS_HEADER>(0);
                if (dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew < 0
                    || dos.e_lfanew > 0x1000 || !Range(dos.e_lfanew, sizeof(nt))
                    || !Accessible(data + dos.e_lfanew, sizeof(nt))) return false;
                nt = Read<IMAGE_NT_HEADERS64>(dos.e_lfanew);
                if (nt.Signature != IMAGE_NT_SIGNATURE || nt.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64
                    || nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC
                    || nt.OptionalHeader.SizeOfImage != bytes || nt.FileHeader.NumberOfSections == 0
                    || nt.FileHeader.NumberOfSections > 96
                    || nt.FileHeader.SizeOfOptionalHeader != sizeof(IMAGE_OPTIONAL_HEADER64)
                    || nt.OptionalHeader.NumberOfRvaAndSizes < IMAGE_NUMBEROF_DIRECTORY_ENTRIES) return false;
                const auto at = static_cast<std::uint32_t>(dos.e_lfanew) + sizeof(nt);
                const auto sectionBytes = nt.FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER);
                if (!Range(at, sectionBytes) || !Accessible(data + at, sectionBytes)) return false;
                std::memcpy(sections, data + at, sectionBytes);
                std::uint32_t previousEnd = nt.OptionalHeader.SizeOfHeaders;
                for (unsigned i = 0; i < nt.FileHeader.NumberOfSections; ++i)
                {
                    const auto& s = sections[i];
                    if (!Range(s.VirtualAddress, s.Misc.VirtualSize) || s.VirtualAddress < previousEnd
                        || ((s.Characteristics & IMAGE_SCN_MEM_EXECUTE) && (s.Characteristics & IMAGE_SCN_MEM_WRITE))) return false;
                    previousEnd = s.VirtualAddress + s.Misc.VirtualSize;
                    // Discarded relocation/debug sections are not needed for matching.
                    available[i] = (s.Characteristics & IMAGE_SCN_MEM_READ)
                        && !(s.Characteristics & IMAGE_SCN_MEM_DISCARDABLE)
                        && Accessible(data + s.VirtualAddress, s.Misc.VirtualSize);
                }
                const auto& exception = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
                if (!exception.Size || exception.Size % sizeof(RUNTIME_FUNCTION)
                    || !In(exception.VirtualAddress, exception.Size, Section::ReadOnly)) return false;
                functions = reinterpret_cast<const RUNTIME_FUNCTION*>(data + exception.VirtualAddress);
                functionCount = exception.Size / sizeof(RUNTIME_FUNCTION);
                if (functionCount > 65536) return false;
                std::uint32_t last = 0;
                for (unsigned i = 0; i < functionCount; ++i)
                {
                    const auto& f = functions[i];
                    if (f.BeginAddress <= last || f.EndAddress <= f.BeginAddress
                        || !In(f.BeginAddress, f.EndAddress - f.BeginAddress, Section::Code)) return false;
                    last = f.BeginAddress;
                }
                return true;
            }

            bool Import(std::uint32_t iat, const char* name) const
            {
                const auto& dir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
                if (!In(dir.VirtualAddress, dir.Size, Section::ReadOnly)) return false;
                for (std::uint32_t offset = 0; offset + sizeof(IMAGE_IMPORT_DESCRIPTOR) <= dir.Size;
                    offset += sizeof(IMAGE_IMPORT_DESCRIPTOR))
                {
                    const auto desc = Read<IMAGE_IMPORT_DESCRIPTOR>(dir.VirtualAddress + offset);
                    if (!desc.Name) break;
                    if (iat < desc.FirstThunk || (iat - desc.FirstThunk) % 8 || !desc.OriginalFirstThunk) continue;
                    const auto thunk = static_cast<std::uint64_t>(desc.OriginalFirstThunk) + iat - desc.FirstThunk;
                    if (thunk > UINT32_MAX || !In(static_cast<std::uint32_t>(thunk), 8, Section::ReadOnly)) continue;
                    const auto nameRva = Read<std::uint64_t>(static_cast<std::uint32_t>(thunk));
                    const auto length = std::strlen(name) + 1;
                    if (nameRva > UINT32_MAX - 2 || !In(static_cast<std::uint32_t>(nameRva), length + 2, Section::ReadOnly)) continue;
                    if (!std::memcmp(data + nameRva + 2, name, length)) return true;
                }
                return false;
            }

            bool Relative(std::uint32_t start, const Reference& ref, std::uint32_t& target) const
            {
                if ((ref.width != 1 && ref.width != 4) || !In(start + ref.displacement, ref.width, Section::Code)) return false;
                const auto address = static_cast<std::int64_t>(start) + ref.nextInstruction
                    + (ref.width == 1 ? Read<std::int8_t>(start + ref.displacement)
                        : Read<std::int32_t>(start + ref.displacement));
                if (address < 0 || address > UINT32_MAX) return false;
                target = static_cast<std::uint32_t>(address);
                return In(target, 1, ref.section) && (!ref.importName || Import(target, ref.importName));
            }

            const RUNTIME_FUNCTION* Function(std::uint32_t start) const
            {
                const auto* found = std::lower_bound(functions, functions + functionCount, start,
                    [](const RUNTIME_FUNCTION& f, std::uint32_t at) { return f.BeginAddress < at; });
                return found != functions + functionCount && found->BeginAddress == start ? found : nullptr;
            }

            bool Owner(RUNTIME_FUNCTION entry, std::uint32_t& root) const
            {
                for (unsigned depth = 0; depth < 16; ++depth)
                {
                    if (!In(entry.UnwindData, 4, Section::ReadOnly)) return false;
                    const auto versionFlags = Read<unsigned char>(entry.UnwindData);
                    if ((versionFlags & 7) != 1 && (versionFlags & 7) != 2) return false;
                    const auto codes = Read<unsigned char>(entry.UnwindData + 2);
                    const auto length = 4u + ((codes + 1u) & ~1u) * 2u;
                    if (!In(entry.UnwindData, length, Section::ReadOnly)) return false;
                    if (!(versionFlags & (UNW_FLAG_CHAININFO << 3)))
                    { root = entry.BeginAddress; return true; }
                    if (versionFlags & ((UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER) << 3)
                        || !In(entry.UnwindData + length, sizeof(entry), Section::ReadOnly)) return false;
                    entry = Read<RUNTIME_FUNCTION>(entry.UnwindData + length);
                    const auto* parent = Function(entry.BeginAddress);
                    if (!parent || parent->EndAddress != entry.EndAddress || parent->UnwindData != entry.UnwindData)
                        return false;
                }
                return false; // Cyclic or unbounded chained unwind records.
            }

            bool Fragments(std::uint32_t start, const Pattern& pattern, std::uint32_t* starts) const
            {
                if (pattern.fragmentCount >= kMaxFragments) return false;
                const auto* first = Function(start);
                std::uint32_t root = 0;
                if (!first || !Owner(*first, root) || root != start
                    || pattern.length > first->EndAddress - start) return false;
                starts[0] = start;
                unsigned count = 0;
                for (unsigned i = 0; i < functionCount; ++i)
                {
                    const auto& f = functions[i];
                    if (f.BeginAddress == start) continue;
                    if (!Owner(f, root)) return false;
                    if (root != start) continue;
                    if (count >= pattern.fragmentCount
                        || pattern.fragments[count].length > f.EndAddress - f.BeginAddress) return false;
                    starts[++count] = f.BeginAddress;
                }
                return count == pattern.fragmentCount;
            }
        };

        template<class T> bool Match(const Image& image, std::uint32_t start, const T& pattern)
        {
            if (!image.In(start, pattern.length, Section::Code)) return false;
            const auto* bytes = image.data + start;
            for (unsigned i = 0; i < pattern.length; ++i)
                if ((bytes[i] & pattern.mask[i]) != pattern.bytes[i]) return false;
            return true;
        }

        bool Bind(std::uint32_t& binding, std::uint32_t value)
        {
            if (!value || (binding && binding != value)) return false;
            binding = value;
            return true;
        }

        bool WindowListOffset(const Image& image, Resolved& result)
        {
            // mov rax,[rip+manager]; mov rcx,[rax+field]; call FindWindowDataByHwnd
            // There can be several equivalent call sites. Every qualified site
            // must agree on the field. No fallback to a build-specific offset.
            constexpr unsigned char first[] = {0x48,0x8b,0x05};
            constexpr unsigned char second[] = {0x48,0x8b,0x88};
            unsigned matches = 0;
            for (unsigned s = 0; s < image.nt.FileHeader.NumberOfSections; ++s)
            {
                const auto& section = image.sections[s];
                if (!image.available[s] || !(section.Characteristics & IMAGE_SCN_MEM_EXECUTE)
                    || section.Misc.VirtualSize < 19) continue;
                const auto end = section.VirtualAddress + section.Misc.VirtualSize - 19;
                for (auto rva = section.VirtualAddress; rva <= end; ++rva)
                {
                    const auto* p = image.data + rva;
                    if (std::memcmp(p, first, 3) || std::memcmp(p + 7, second, 3) || p[14] != 0xe8) continue;
                    std::uint32_t manager = 0, find = 0;
                    if (!image.Relative(rva, {3,7,Section::Writable,Node::Count,Binding::None,nullptr}, manager)
                        || !image.Relative(rva, {15,19,Section::Code,Node::Count,Binding::None,nullptr}, find)
                        || manager != result.desktopManager || find != result.functions[static_cast<unsigned>(Node::FindWindow)]) continue;
                    const auto field = image.Read<std::uint32_t>(rva + 10);
                    if (field < 8 || field > 0x1000 || field % 8 || !Bind(result.windowListOffset, field)) return false;
                    ++matches;
                }
            }
            return matches >= 2;
        }

        bool Vtable(const Image& image, Resolved& result)
        {
            unsigned hits[3]{};
            const Node roles[] = {Node::DestroyWindow, Node::ZOrder, Node::UpdateScene};
            std::uint32_t* slots[] = {&result.destroySlot, &result.zOrderSlot, &result.updateSlot};
            for (unsigned i = 0; i < 128; ++i)
            {
                const auto entry = result.vtable + i * 8;
                if (!image.In(entry, 8, Section::ReadOnly)) break;
                const auto address = image.Read<std::uint64_t>(entry);
                if (address < image.base || address - image.base > UINT32_MAX
                    || !image.In(static_cast<std::uint32_t>(address - image.base), 1, Section::Code)) break;
                for (unsigned role = 0; role < 3; ++role)
                    if (address - image.base == result.functions[static_cast<unsigned>(roles[role])])
                    { ++hits[role]; *slots[role] = i; }
                ++result.tableSlots;
            }
            // MSVC may place unrelated vtables directly after this one without
            // a null/RTTI delimiter. Only the prefix through our last hook is
            // published; never infer a table's length from a null terminator.
            result.tableSlots = (std::max)({result.destroySlot, result.zOrderSlot, result.updateSlot}) + 1;
            return hits[0] == 1 && hits[1] == 1 && hits[2] == 1;
        }

        bool Cfg(const Image& image, const Resolved& result)
        {
            const auto& dir = image.nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
            if (dir.Size < 148 || !image.In(dir.VirtualAddress, 148, Section::ReadOnly)
                || image.Read<std::uint32_t>(dir.VirtualAddress) < 148) return false;
            const auto table = image.Read<std::uint64_t>(dir.VirtualAddress + 128);
            const auto count = image.Read<std::uint64_t>(dir.VirtualAddress + 136);
            const auto flags = image.Read<std::uint32_t>(dir.VirtualAddress + 144);
            const auto stride = 4 + ((flags >> 28) & 15);
            if ((flags & 0x500) != 0x500 || table < image.base || table - image.base > UINT32_MAX
                || !count || count > 65536 || !image.In(static_cast<std::uint32_t>(table - image.base),
                    static_cast<std::size_t>(count * stride), Section::ReadOnly)) return false;
            unsigned valid = 0;
            const Node roles[] = {Node::DestroyWindow, Node::ZOrder, Node::UpdateScene};
            std::uint32_t previous = 0;
            for (std::uint64_t i = 0; i < count; ++i)
            {
                const auto entry = static_cast<std::uint32_t>(table - image.base + i * stride);
                const auto rva = image.Read<std::uint32_t>(entry);
                if (rva <= previous || !image.In(rva, 1, Section::Code)) return false;
                previous = rva;
                for (auto role : roles)
                    if (rva == result.functions[static_cast<unsigned>(role)])
                    {
                        if (stride > 4 && (image.Read<unsigned char>(entry + 4) & 1)) return false;
                        ++valid;
                    }
            }
            // The two private helpers stay behind the reviewed nocf bridge;
            // their presence/absence in GFIDS may vary across serviced images.
            return valid == 3;
        }

        Failure ResolveModel(const Image& image, const Model& model, Resolved& result,
            Node* failedNode, unsigned& progress)
        {
            const Pattern* chosen[kNodes]{};
            std::uint32_t fragmentStarts[kNodes][kMaxFragments]{};
            for (unsigned node = 0; node < kNodes; ++node)
            {
                bool required = false;
                for (std::size_t p = 0; p < model.patternCount; ++p)
                    required |= static_cast<unsigned>(model.patterns[p].node) == node;
                if (!required) continue;
                if (failedNode) *failedNode = static_cast<Node>(node);
                for (std::size_t p = 0; p < model.patternCount; ++p)
                {
                    const auto& pattern = model.patterns[p];
                    if (static_cast<unsigned>(pattern.node) != node) continue;
                    for (unsigned i = 0; i < image.functionCount; ++i)
                    {
                        const auto rva = image.functions[i].BeginAddress;
                        if (!Match(image, rva, pattern)) continue;
                        std::uint32_t starts[kMaxFragments]{rva};
                        if (model.fragmented)
                        {
                            if (!image.Fragments(rva, pattern, starts)) return Failure::InvalidFragments;
                            bool matches = true;
                            for (unsigned f = 0; f < pattern.fragmentCount; ++f)
                                matches &= Match(image, starts[f + 1], pattern.fragments[f]);
                            if (!matches) continue;
                        }
                        if (result.functions[node] && result.functions[node] != rva) return Failure::AmbiguousPattern;
                        // Even variants sharing byte masks must agree on all
                        // reference roles; the generator deduplicates those.
                        if (chosen[node] && chosen[node] != &pattern) return Failure::AmbiguousPattern;
                        result.functions[node] = rva;
                        chosen[node] = &pattern;
                        std::memcpy(fragmentStarts[node], starts, sizeof(starts));
                    }
                }
                if (!chosen[node]) return Failure::MissingPattern;
                ++progress;
            }
            for (unsigned node = 0; node < kNodes; ++node)
            {
                if (!chosen[node]) continue;
                if (failedNode) *failedNode = static_cast<Node>(node);
                const auto& pattern = *chosen[node];
                for (unsigned f = 0; f <= pattern.fragmentCount; ++f)
                {
                    const auto* refs = f ? pattern.fragments[f - 1].references : pattern.references;
                    const auto count = f ? pattern.fragments[f - 1].referenceCount : pattern.referenceCount;
                    for (unsigned i = 0; i < count; ++i)
                    {
                        const auto& ref = refs[i];
                        std::uint32_t target = 0;
                        if (!image.Relative(fragmentStarts[node][f], ref, target)
                            || (ref.node != Node::Count && target != result.functions[static_cast<unsigned>(ref.node)]))
                            return Failure::ReferenceMismatch;
                        if (ref.targetFragment != UINT16_MAX)
                        {
                            if (ref.targetFragment > pattern.fragmentCount) return Failure::ReferenceMismatch;
                            const auto length = ref.targetFragment ? pattern.fragments[ref.targetFragment - 1].length : pattern.length;
                            if (ref.targetOffset >= length
                                || target != fragmentStarts[node][ref.targetFragment] + ref.targetOffset)
                                return Failure::ReferenceMismatch;
                        }
                        std::uint32_t* slot = ref.binding == Binding::DesktopManager ? &result.desktopManager
                            : ref.binding == Binding::CriticalSection ? &result.criticalSection
                            : ref.binding == Binding::Vtable ? &result.vtable : nullptr;
                        if (slot && !Bind(*slot, target)) return Failure::ReferenceMismatch;
                    }
                }
            }
            if (failedNode) *failedNode = Node::Count;
            if (!image.In(result.desktopManager, 8, Section::Writable)
                || !image.In(result.criticalSection, sizeof(CRITICAL_SECTION), Section::Writable)
                || result.desktopManager % 8 || result.criticalSection % 8) return Failure::ReferenceMismatch;
            if (!Vtable(image, result)) return Failure::InvalidVtable;
            if (!Cfg(image, result)) return Failure::InvalidCfg;
            if (!WindowListOffset(image, result)) return Failure::InvalidWindowList;
            result.layout = model.layout;
            result.model = model.id;
            return Failure::None;
        }
    }

    Failure Resolve(const void* image, std::size_t bytes, std::uintptr_t loadBase,
        Resolved& result, Node* failedNode)
    {
        result = {};
        if (failedNode) *failedNode = Node::Count;
        Image input{static_cast<const unsigned char*>(image), bytes, loadBase};
        if (!input.Open()) return Failure::InvalidImage;
        Failure bestFailure = Failure::MissingPattern;
        unsigned bestProgress = 0;
        Node bestNode = Node::Count;
        Resolved selected{};
        for (const auto& model : kModels)
        {
            Resolved candidate{};
            unsigned progress = 0;
            Node node = Node::Count;
            const auto failure = ResolveModel(input, model, candidate, &node, progress);
            if (failure == Failure::None)
            {
                if (selected.model) return Failure::AmbiguousPattern;
                selected = candidate;
            }
            else if (progress >= bestProgress)
            { bestFailure = failure; bestProgress = progress; bestNode = node; }
        }
        if (selected.model) { result = selected; return Failure::None; }
        if (failedNode) *failedNode = bestNode;
        return bestFailure;
    }
}
