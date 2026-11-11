#include "pch.h"
#include "HookEngine.h"
#include "../core/MonitorDiagnostics.h"
#include "NearAllocation.h"
#include "ThreadPatchGuard.h"
#include "CodePageAllocator.h"

#include <TlHelp32.h>
#include <intrin.h>
#include <map>

extern "C" unsigned long _tls_index;

namespace apimon
{
    namespace
    {
#ifdef _M_IX86
        constexpr std::size_t kAbsoluteJumpSize = 5;
        constexpr char kLandingPad[] = "\xF3\x0F\x1E\xFB";
#else
        constexpr std::size_t kAbsoluteJumpSize = 14;
        constexpr char kLandingPad[] = "\xF3\x0F\x1E\xFA";
#endif
        thread_local std::uint32_t g_inlineHookInternalBypassDepth = 0; // g_inlineHookInternalBypassDepth：HookEngine 内部操作重入屏蔽深度。
        thread_local HookInstallStopCheck g_installStopCheck = nullptr;

        // Loader callbacks can still enter patched APIs after this thread's static TLS is freed.
        // Do not call a TLS getter or another monitored API while checking its availability.
        bool HookThreadStorageAvailable() noexcept
        {
#ifdef _M_IX86
            auto** slots = reinterpret_cast<void**>(__readfsdword(0x2C));
#else
            auto** slots = reinterpret_cast<void**>(__readgsqword(0x58));
#endif
            if (!slots) return false;
            __try { return slots[_tls_index] != nullptr; }
            __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
        }

        using ScopedOtherThreadsSuspender = detail::ThreadPatchGuard;

        enum class ControlFlow { Linear, Call, Jump, Conditional, LandingPad, Terminal };
        struct InstructionDescription
        {
            std::size_t length = 0;
            std::size_t displacementOffset = 0;
            unsigned displacementSize = 0;
            bool ripRelative = false;
            bool indirectCall = false;
            ControlFlow flow = ControlFlow::Linear;
            unsigned condition = 0;
            std::int64_t relativeDisplacement = 0;
        };

#ifdef _M_IX86
#include "../../APIMonitor_x86/hook/InstructionDecoder.inc"
#else
        InstructionDescription DecodeInstruction(const unsigned char* code, std::size_t size)
        {
            InstructionDescription d;
            if (!code || !size) return d;
            size = (std::min)(size, std::size_t(15));
            if (size >= 4 && code[0] == 0xF3 && code[1] == 0x0F && code[2] == 0x1E && code[3] == 0xFA)
            { d.length = 4; d.flow = ControlFlow::LandingPad; return d; }
            // Windows x64 commonly begins with a stack adjustment followed by
            // `48 FF 15 disp32` (CALL through a RIP-relative import slot).
            // This exact form is linear from the trampoline's point of view:
            // the callee returns to the next relocated instruction. Reuse the
            // existing bounded RIP-relative relocation; do not accept other FF
            // groups, prefixes or indirect jumps by guessing their semantics.
            if (size >= 3 && code[0] == 0x48 && code[1] == 0xFF && code[2] == 0x15)
            {
                if (size < 7) return d;
                std::int32_t displacement{};
                std::memcpy(&displacement, code + 3, sizeof(displacement));
                d.length = 7; d.displacementOffset = 3; d.displacementSize = 4;
                d.ripRelative = true; d.indirectCall = true; d.relativeDisplacement = displacement;
                return d;
            }
            std::size_t offset = 0;
            bool operand16 = false, rexW = false, seenRex = false;
            while (offset < size)
            {
                const unsigned char p = code[offset];
                if (p == 0x66) { if (seenRex) return {}; operand16 = true; ++offset; }
                else if (p >= 0x40 && p <= 0x4F) { if (seenRex) return {}; seenRex = true; rexW = (p & 8) != 0; ++offset; }
                else if (p == 0x2E || p == 0x36 || p == 0x3E || p == 0x26 || p == 0x64 || p == 0x65) { if (seenRex) return {}; ++offset; }
                else break;
            }
            if (offset >= size) return {};
            const unsigned char op = code[offset++];
            // Address override, vector encodings, lock/rep outside ENDBR, and undocumented opcodes are rejected.
            if (op == 0x67 || op == 0xF0 || op == 0xF2 || op == 0xF3) return {};
            auto finish = [&](std::size_t immediate) -> InstructionDescription {
                if (offset + immediate > size) return {};
                d.length = offset + immediate; return d;
            };
            auto relative = [&](ControlFlow flow, unsigned width, unsigned condition = 0) -> InstructionDescription {
                if (offset + width > size || offset != (op == 0x0F ? 2u : 1u)) return {};
                d.flow = flow; d.condition = condition; d.displacementOffset = offset;
                d.displacementSize = width;
                if (width == 1) d.relativeDisplacement = static_cast<std::int8_t>(code[offset]);
                else { std::int32_t value; std::memcpy(&value, code + offset, 4); d.relativeDisplacement = value; }
                return finish(width);
            };
            if ((op >= 0x50 && op <= 0x5F) || op == 0x90) return finish(0);
            if (op == 0xC3 || op == 0xC2 || op == 0xCC) { d.flow = ControlFlow::Terminal; return finish(op == 0xC2 ? 2 : 0); }
            if (op == 0x6A) return finish(1);
            if (op == 0x68) return finish(operand16 ? 2 : 4);
            if (op >= 0xB8 && op <= 0xBF) return finish(rexW ? 8 : operand16 ? 2 : 4);
            if (op == 0xE8 || op == 0xE9) return relative(op == 0xE8 ? ControlFlow::Call : ControlFlow::Jump, 4);
            if (op == 0xEB) return relative(ControlFlow::Jump, 1);
            if (op >= 0x70 && op <= 0x7F) return relative(ControlFlow::Conditional, 1, op & 15);
            unsigned char second = 0;
            if (op == 0x0F)
            {
                if (offset >= size) return {};
                second = code[offset++];
                if (second >= 0x80 && second <= 0x8F) return relative(ControlFlow::Conditional, 4, second & 15);
                // Only NOP, register/memory extensions and conditional moves with known ModRM layout.
                if (second != 0x1F && second != 0xB6 && second != 0xB7 && second != 0xBE && second != 0xBF
                    && !(second >= 0x40 && second <= 0x4F)) return {};
            }
            std::size_t immediate = 0;
            if (op != 0x0F)
            {
                switch (op)
                {
                case 0x01: case 0x03: case 0x09: case 0x0B: case 0x21: case 0x23: case 0x29: case 0x2B:
                case 0x31: case 0x33: case 0x39: case 0x3B: case 0x63: case 0x84: case 0x85:
                case 0x88: case 0x89: case 0x8A: case 0x8B: case 0x8D: break;
                case 0x81: case 0xC7: immediate = operand16 && !rexW ? 2 : 4; break;
                case 0x80: case 0x83: case 0xC6: immediate = 1; break;
                case 0xF6: case 0xF7:
                    if (offset >= size) return {};
                    if (((code[offset] >> 3) & 7) == 1) return {};
                    if (((code[offset] >> 3) & 7) == 0) immediate = op == 0xF6 ? 1 : operand16 && !rexW ? 2 : 4;
                    break;
                // Indirect CALL/JMP remains a boundary; entry FF25 stubs are resolved separately.
                default: return {};
                }
            }
            if (offset >= size) return {};
            const unsigned char modrm = code[offset++];
            const unsigned mod = modrm >> 6, rm = modrm & 7, group = (modrm >> 3) & 7;
            if ((op == 0xC6 || op == 0xC7 || (op == 0x0F && second == 0x1F)) && group != 0) return {};
            if (op == 0x8D && mod == 3) return {};
            unsigned displacement = 0;
            if (mod != 3 && rm == 4)
            {
                if (offset >= size) return {};
                const unsigned base = code[offset++] & 7;
                if (mod == 0 && base == 5) displacement = 4;
            }
            if (mod == 0 && rm == 5) { displacement = 4; d.ripRelative = true; }
            if (mod == 1) displacement = 1;
            if (mod == 2) displacement = 4;
            if (displacement)
            {
                d.displacementOffset = offset; d.displacementSize = displacement;
                if (offset + displacement > size) return {};
                if (d.ripRelative) { std::int32_t value; std::memcpy(&value, code + offset, 4); d.relativeDisplacement = value; }
                offset += displacement;
            }
            return finish(immediate);
        }

#endif
        bool SafeRead(const void* source, void* destination, std::size_t size)
        {
            const auto begin = reinterpret_cast<std::uintptr_t>(source);
            if (!begin || size > UINTPTR_MAX - begin) return false;
            auto position = begin;
            while (position < begin + size)
            {
                MEMORY_BASIC_INFORMATION info{};
                if (!::VirtualQuery(reinterpret_cast<void*>(position), &info, sizeof(info)) || info.State != MEM_COMMIT
                    || (info.Protect & (PAGE_NOACCESS | PAGE_GUARD))) return false;
                const auto end = reinterpret_cast<std::uintptr_t>(info.BaseAddress) + static_cast<std::uintptr_t>(info.RegionSize);
                if (end <= position) return false;
                position = (std::min)(end, begin + size);
            }
            __try { std::memcpy(destination, source, size); return true; }
            __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
        }

        std::size_t ReadCode(const void* source, unsigned char* destination, std::size_t capacity)
        {
            // Inspect each memory region once. Per-byte VirtualQuery plus
            // SafeRead caused 64 queries just to inspect a 32-byte entry.
            // Copy only the readable prefix; never touch an inaccessible suffix.
            std::size_t size = 0;
            while (size < capacity)
            {
                const auto position = reinterpret_cast<std::uintptr_t>(source) + size;
                if (position < reinterpret_cast<std::uintptr_t>(source)) break;
                MEMORY_BASIC_INFORMATION info{};
                if (!::VirtualQuery(reinterpret_cast<const void*>(position), &info, sizeof(info))
                    || info.State != MEM_COMMIT || (info.Protect & (PAGE_NOACCESS | PAGE_GUARD))
                    || !(info.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) break;
                const auto base = reinterpret_cast<std::uintptr_t>(info.BaseAddress);
                if (info.RegionSize > UINTPTR_MAX - base || base + info.RegionSize <= position) break;
                const auto count = (std::min)(capacity - size, static_cast<std::size_t>(base + info.RegionSize - position));
                __try { std::memcpy(destination + size, reinterpret_cast<const void*>(position), count); }
                __except (EXCEPTION_EXECUTE_HANDLER) { break; }
                size += count;
            }
            return size;
        }

        bool FitsRel32(std::int64_t value)
        {
#ifdef _M_IX86
            // rel32 reaches every 32-bit address using modular arithmetic.
            (void)value; return true;
#else
            return value >= INT32_MIN && value <= INT32_MAX;
#endif
        }

        std::size_t RelocatedSize(const InstructionDescription& instruction)
        {
            if (instruction.flow == ControlFlow::Conditional) return 6;
            if (instruction.flow == ControlFlow::Call || instruction.flow == ControlFlow::Jump) return 5;
            return instruction.length;
        }

        bool BuildRelocatedCode(const unsigned char* original, std::uintptr_t source,
            std::size_t patchSize, unsigned char* output, std::uintptr_t destination,
            const std::vector<InstructionDescription>& instructions, std::size_t* outputSize,
            std::size_t* failureOffset, const wchar_t** reason)
        {
            std::array<std::size_t, 33> oldOffsets{}, newOffsets{};
            std::size_t oldOffset = 0, newOffset = 0;
            for (std::size_t i = 0; i < instructions.size(); ++i)
            { oldOffsets[i] = oldOffset; newOffsets[i] = newOffset; oldOffset += instructions[i].length; newOffset += RelocatedSize(instructions[i]); }
            for (std::size_t i = 0; i < instructions.size(); ++i)
            {
                const auto& instruction = instructions[i];
                const std::size_t from = oldOffsets[i], to = newOffsets[i], emitted = RelocatedSize(instruction);
                *failureOffset = from;
                if (instruction.flow == ControlFlow::Call || instruction.flow == ControlFlow::Jump || instruction.flow == ControlFlow::Conditional)
                {
                    const std::uintptr_t targetValue = static_cast<std::uintptr_t>(source + from + instruction.length + instruction.relativeDisplacement);
                    std::uintptr_t target = targetValue;
                    if (target >= source && target < source + patchSize)
                    {
                        const auto end = oldOffsets.begin() + instructions.size();
                        const auto found = std::find(oldOffsets.begin(), end, target - source);
                        if (found == end) { *reason = L"branch enters the middle of an overwritten instruction"; return false; }
                        target = destination + newOffsets[found - oldOffsets.begin()];
                    }
                    const auto delta = static_cast<std::int64_t>(target) - static_cast<std::int64_t>(destination + to + emitted);
                    if (!FitsRel32(delta)) { *reason = L"relative control-flow target exceeds rel32 range"; return false; }
                    if (instruction.flow == ControlFlow::Conditional)
                    { output[to] = 0x0F; output[to + 1] = static_cast<unsigned char>(0x80 | instruction.condition); }
                    else output[to] = instruction.flow == ControlFlow::Call ? 0xE8 : 0xE9;
                    const std::int32_t displacement = static_cast<std::int32_t>(delta);
                    std::memcpy(output + to + emitted - 4, &displacement, 4);
                }
                else
                {
                    std::memcpy(output + to, original + from, instruction.length);
                    if (instruction.ripRelative)
                    {
                        const auto target = source + from + instruction.length + instruction.relativeDisplacement;
                        // An indirect CALL reads a full pointer from its slot,
                        // so a slot starting immediately before the patch can
                        // also overlap bytes that will be overwritten.
                        const bool overlapsStart = target >= source && target < source + patchSize;
                        const bool overlapsPointerTail = instruction.indirectCall && target < source
                            && source - target < sizeof(std::uintptr_t);
                        if (overlapsStart || overlapsPointerTail)
                        { *reason = L"RIP-relative data overlaps the entry patch"; return false; }
                        const auto delta = static_cast<std::int64_t>(target) - static_cast<std::int64_t>(destination + to + instruction.length);
                        if (!FitsRel32(delta)) { *reason = L"RIP-relative operand exceeds disp32 range"; return false; }
                        const std::int32_t displacement = static_cast<std::int32_t>(delta);
                        std::memcpy(output + to + instruction.displacementOffset, &displacement, 4);
                    }
                }
            }
            *outputSize = newOffset;
            return true;
        }

        unsigned char* AllocateNear(const void* target)
        {
            APIMON_DIAG_ADD(NearCalls,1);
            APIMON_DIAG_SCOPE(NearTicks);
#ifdef _M_IX86
            (void)target;
            return detail::AllocateCodePage();
#else
            return detail::AllocateNearAddress(target,&HookInstallationCancelled);
#endif
        }

        // BuildAbsoluteJump 作用：
        // - 输入：targetBuffer 指向至少 kAbsoluteJumpSize 字节可写内存，destinationAddress 为跳转目标；
        // - 处理：写入 x64 RIP 间接绝对跳转桩，避免 mov rax/jmp rax 破坏 trampoline 已恢复的 RAX；
        // - 返回：无返回值，调用者随后负责刷新指令缓存。
        void BuildAbsoluteJump(unsigned char* targetBuffer, const void* destinationAddress)
        {
#ifdef _M_IX86
            targetBuffer[0] = 0xE9;
            const std::uint32_t delta = reinterpret_cast<std::uintptr_t>(destinationAddress)
                - (reinterpret_cast<std::uintptr_t>(targetBuffer) + 5);
            std::memcpy(targetBuffer + 1, &delta, 4);
#else
            targetBuffer[0] = 0xFF;
            targetBuffer[1] = 0x25;
            targetBuffer[2] = 0x00;
            targetBuffer[3] = 0x00;
            targetBuffer[4] = 0x00;
            targetBuffer[5] = 0x00;
            std::memcpy(targetBuffer + 6, &destinationAddress, sizeof(destinationAddress));
#endif
        }

        struct EntryPatch
        {
            unsigned char* target = nullptr;
            void* detour = nullptr;
            unsigned char* trampoline = nullptr;
            std::size_t size = 0;
            std::array<unsigned char, 32> original{}, patched{};
            unsigned references = 0;
            bool active = false;
            bool pending = false;
            bool bulkRestored = false;
        };
        auto& g_engineMutex = *new std::recursive_mutex;
        // Stable contexts and published executable code are retained through process exit.
        auto& g_entryPatches = *new std::vector<std::unique_ptr<EntryPatch>>;
        // Retired code stays alive, but only active/prepared intervals belong
        // in lookup. Scanning the lifetime vector made setup quadratic and
        // slowed every subsequent session as retired entries accumulated.
        auto& g_activeEntries = *new std::map<std::uintptr_t,EntryPatch*>;
        EntryPatch* FindPatchContaining(std::uintptr_t address)
        {
            auto after = g_activeEntries.upper_bound(address);
            if (after == g_activeEntries.begin()) return nullptr;
            const auto entry = *std::prev(after);
            return address - entry.first < entry.second->size ? entry.second : nullptr;
        }
        struct PendingReference { EntryPatch* patch; InlineHookRecord* record; };
        struct PendingBatch { std::vector<EntryPatch*> entries; std::vector<PendingReference> references; };
        thread_local PendingBatch* g_pendingBatch = nullptr;
        struct ProtectionRestore { void* address; std::size_t size; DWORD protection; };
        auto& g_pendingProtectionRestores = *new std::vector<ProtectionRestore>;
        bool RetryProtectionRestores()
        {
            std::size_t remaining = 0;
            for (const auto& page : g_pendingProtectionRestores) {
                DWORD ignored = 0;
                if (!::VirtualProtect(page.address, page.size, page.protection, &ignored))
                    g_pendingProtectionRestores[remaining++] = page;
            }
            g_pendingProtectionRestores.resize(remaining);
            return remaining == 0;
        }

        // Prepare protection records and all result storage before freezing.
        // A single captured context set is valid for every entry in this one
        // suspended interval; it is never reused after Resume().
        bool ApplyPatchEntries(const std::vector<EntryPatch*>& entries, bool restore, std::vector<unsigned char>& applied, std::wstring* failure = nullptr)
        {
            applied.assign(entries.size(),0);
            // Keep the original protection until a failed restore has actually
            // succeeded. A later pass must not mistake temporary RWX for it.
            if (!RetryProtectionRestores()) return false;
            if(entries.empty())return true;
            struct Page { unsigned char* address; DWORD old=0; bool changed=false; };
            SYSTEM_INFO info{};::GetSystemInfo(&info);const auto pageSize=static_cast<std::uintptr_t>(info.dwPageSize);
            std::vector<Page> pages;pages.reserve(entries.size()*2);
            for(const auto* entry:entries){
                const auto begin=reinterpret_cast<std::uintptr_t>(entry->target)&~(pageSize-1);
                const auto end=(reinterpret_cast<std::uintptr_t>(entry->target)+entry->size-1)&~(pageSize-1);
                pages.push_back({reinterpret_cast<unsigned char*>(begin)});
                if(end!=begin)pages.push_back({reinterpret_cast<unsigned char*>(end)});
            }
            std::sort(pages.begin(),pages.end(),[](const auto& a,const auto& b){return reinterpret_cast<std::uintptr_t>(a.address)<reinterpret_cast<std::uintptr_t>(b.address);});
            pages.erase(std::unique(pages.begin(),pages.end(),[](const auto& a,const auto& b){return a.address==b.address;}),pages.end());
            const auto restorePages=[&]{bool ok=true;for(auto& page:pages)if(page.changed){DWORD ignored=0;if(::VirtualProtect(page.address,pageSize,page.old,&ignored))page.changed=false;else ok=false;}return ok;};
            const auto retainFailedRestores=[&]{for(const auto& page:pages)if(page.changed)g_pendingProtectionRestores.push_back({page.address,pageSize,page.old});};
            for(auto& page:pages){
                if(!::VirtualProtect(page.address,pageSize,PAGE_EXECUTE_READWRITE,&page.old)){restorePages();retainFailedRestores();return false;}
                page.changed=true;
            }
            ScopedOtherThreadsSuspender suspended;
            const bool contexts=suspended.CaptureContexts();
            bool all=contexts;
            if(contexts){
                for(std::size_t i=0;i<entries.size();++i){
                    auto* entry=entries[i];unsigned char current[32]{};
                    const auto& expected=restore?entry->patched:entry->original;
                    if(!suspended.AllowsPatch(entry->target,entry->size)||!SafeRead(entry->target,current,entry->size)
                        ||std::memcmp(current,expected.data(),entry->size)!=0){all=false;continue;}
                    std::memcpy(entry->target,(restore?entry->original:entry->patched).data(),entry->size);
                    applied[i]=1;
                }
                for(const auto& page:pages)::FlushInstructionCache(::GetCurrentProcess(),page.address,pageSize);
            }
            const bool protectedAgain=restorePages();
            suspended.Resume();
            if (failure) {
                if (!contexts) *failure=suspended.FailureText();
                else if (!all) *failure=L"batch entry changed or thread in patch region; retry required";
                else if (!protectedAgain) *failure=L"page protection restore failed; retry required";
            }
            retainFailedRestores();
            return all&&protectedAgain;
        }

        void* ResolveJumpStub(void* entry, std::size_t* failureOffset, const wchar_t** reason)
        {
            std::array<void*, 16> visited{};
            auto* current = static_cast<unsigned char*>(entry);
            for (std::size_t depth = 0; depth < visited.size(); ++depth)
            {
                *failureOffset = 0;
                if (!current) { *reason = L"null jump-stub target"; return nullptr; }
                if (std::find(visited.begin(), visited.begin() + depth, current) != visited.begin() + depth)
                { *reason = L"jump-stub cycle"; return nullptr; }
                visited[depth] = current;
                if (FindPatchContaining(reinterpret_cast<std::uintptr_t>(current))) return current;
                unsigned char bytes[32]{};
                const auto readable = ReadCode(current, bytes, sizeof(bytes));
                if (!readable) { *reason = L"unreadable or non-executable entry"; return nullptr; }
                // Keep the exported ENDBR entry intact; relocation starts after it.
                if (readable >= 4 && std::memcmp(bytes, kLandingPad, 4) == 0) return current;
                if (bytes[0] == 0xE9 || bytes[0] == 0xEB)
                {
                    const auto d = DecodeInstruction(bytes, readable);
                    if (!d.length) { *reason = L"truncated entry jump"; return nullptr; }
                    current = reinterpret_cast<unsigned char*>(reinterpret_cast<std::uintptr_t>(current) + d.length + d.relativeDisplacement);
                    continue;
                }
#ifdef _M_IX86
                const bool rexIndirect = false;
#else
                const bool rexIndirect = readable >= 3 && bytes[0] == 0x48 && bytes[1] == 0xFF && bytes[2] == 0x25;
#endif
                if ((readable >= 2 && bytes[0] == 0xFF && bytes[1] == 0x25) || rexIndirect)
                {
                    const std::size_t prefix = rexIndirect ? 1 : 0;
                    if (readable < prefix + 6) { *reason = L"truncated indirect entry jump"; return nullptr; }
                    std::int32_t displacement{};
                    std::memcpy(&displacement, bytes + prefix + 2, 4);
                    void* next = nullptr;
#ifdef _M_IX86
                    const auto slot = static_cast<std::uint32_t>(displacement);
#else
                    const auto slot = reinterpret_cast<std::uintptr_t>(current) + prefix + 6 + displacement;
#endif
                    if (!SafeRead(reinterpret_cast<void*>(slot), &next, sizeof(next)))
                    { *reason = L"unreadable jump-stub pointer"; return nullptr; }
                    current = static_cast<unsigned char*>(next);
                    continue;
                }
                return current;
            }
            *reason = L"jump-stub depth limit exceeded";
            return nullptr;
        }

        std::size_t CalculatePatchSize(const unsigned char* bytes, std::size_t readable,
            std::size_t required, std::vector<InstructionDescription>* instructions,
            std::size_t* failureOffset, const wchar_t** reason)
        {
            std::size_t offset = 0;
            while (offset < required)
            {
                *failureOffset = offset;
                const auto d = DecodeInstruction(bytes + offset, readable - offset);
                if (!d.length) { *reason = L"unsupported or truncated instruction (including address override)"; return 0; }
                if (d.flow == ControlFlow::Terminal) { *reason = L"entry ends before a complete patch fits"; return 0; }
                if (offset + d.length > 32) { *reason = L"entry patch exceeds saved-byte capacity"; return 0; }
                instructions->push_back(d);
                offset += d.length;
                if (d.flow == ControlFlow::Jump && offset < required)
                { *reason = L"terminal jump before enough patch bytes"; return 0; }
                if (offset >= readable && offset < required) { *reason = L"unreadable entry suffix"; return 0; }
            }
            return offset;
        }

    }

    bool IsInlineHookInternalBypassActive()
    {
        // IsInlineHookInternalBypassActive 作用：
        // - 输入：无；
        // - 处理：读取当前线程 HookEngine 内部操作深度；
        // - 返回：深度大于 0 返回 true。
        return !HookThreadStorageAvailable() || g_inlineHookInternalBypassDepth != 0;
    }

    ScopedInlineHookInternalBypass::ScopedInlineHookInternalBypass()
    {
        // 构造函数：
        // - 输入：无；
        // - 处理：当前线程进入 HookEngine 内部区间，HookedXXX wrapper 将直接旁路；
        // - 返回：无返回值。
        if (HookThreadStorageAvailable())
        {
            ++g_inlineHookInternalBypassDepth;
            m_entered = true;
        }
    }

    ScopedInlineHookInternalBypass::~ScopedInlineHookInternalBypass()
    {
        // 析构函数：
        // - 输入：无；
        // - 处理：当前线程退出 HookEngine 内部区间，防止安装/卸载结束后继续旁路用户调用；
        // - 返回：无返回值。
        if (m_entered && HookThreadStorageAvailable() && g_inlineHookInternalBypassDepth != 0)
        {
            --g_inlineHookInternalBypassDepth;
        }
    }

    struct InlineHookInstallBatch::State {
        std::unique_lock<std::recursive_mutex> lock{g_engineMutex};
        PendingBatch batch;
        PendingBatch* previous=g_pendingBatch;
        bool finished=false;
    };
    InlineHookInstallBatch::InlineHookInstallBatch() : state(std::make_unique<State>()) {
        if(!state->previous)g_pendingBatch=&state->batch;
    }
    bool InlineHookInstallBatch::commit() {
        if(state->finished)return true;
        state->finished=true;
        if(state->previous)return true;
        std::vector<unsigned char> applied(state->batch.entries.size(),0);
        std::vector<EntryPatch*> remaining=state->batch.entries;
        std::vector<std::size_t> indices(remaining.size());
        for(std::size_t i=0;i<indices.size();++i)indices[i]=i;
        std::wstring failure;
        bool success=false;
        // Threads can exit between enumeration and GetThreadContext. Retry a
        // bounded number of fresh frozen sets, without rewriting accepted
        // entries or reusing instruction pointers after threads resume.
        for(unsigned attempt=0;attempt<3&&!HookInstallationCancelled();++attempt){
            std::vector<unsigned char> accepted;
            success=ApplyPatchEntries(remaining,false,accepted,&failure);
            std::size_t pending=0;
            for(std::size_t i=0;i<remaining.size();++i){
                if(accepted[i])applied[indices[i]]=1;
                else {remaining[pending]=remaining[i];indices[pending++]=indices[i];}
            }
            remaining.resize(pending);indices.resize(pending);
            if(success)break;
            if(attempt<2)::Sleep(10);
        }
        for(std::size_t i=0;i<state->batch.entries.size();++i){
            auto* entry=state->batch.entries[i];entry->pending=false;entry->active=applied[i]!=0;
            if(!entry->active){entry->references=0;g_activeEntries.erase(reinterpret_cast<std::uintptr_t>(entry->target));}
        }
        for(const auto& reference:state->batch.references){
            reference.record->installed=reference.patch->active;
            if(!reference.patch->active)reference.record->lastFailure=failure.empty()?L"batch entry changed, cancelled or thread context unsafe; retry required":failure;
        }
        return success;
    }
    InlineHookInstallBatch::~InlineHookInstallBatch() {
        if(!state->previous){
            if(!state->finished){
                for(auto* entry:state->batch.entries){entry->active=false;entry->pending=false;entry->references=0;g_activeEntries.erase(reinterpret_cast<std::uintptr_t>(entry->target));}
                for(const auto& reference:state->batch.references)reference.record->installed=false;
            }
            g_pendingBatch=state->previous;
        }
    }
    ScopedHookInstallCancellation::ScopedHookInstallCancellation(HookInstallStopCheck check) : previous(g_installStopCheck) {g_installStopCheck=check;}
    ScopedHookInstallCancellation::~ScopedHookInstallCancellation(){g_installStopCheck=previous;}
    bool HookInstallationCancelled(){return g_installStopCheck&&g_installStopCheck();}
    bool RestoreAllInlineHookEntries(){
        ScopedInlineHookInternalBypass bypass;
        const std::lock_guard<std::recursive_mutex> lock(g_engineMutex);
        if(g_pendingBatch)return false;
        std::vector<EntryPatch*> active;active.reserve(g_activeEntries.size());
        for(const auto& entry:g_activeEntries)active.push_back(entry.second);
        std::vector<unsigned char> applied;
        const bool success=ApplyPatchEntries(active,true,applied);
        for(std::size_t i=0;i<active.size();++i)if(applied[i]){
            active[i]->active=false;active[i]->references=0;active[i]->bulkRestored=true;
            g_activeEntries.erase(reinterpret_cast<std::uintptr_t>(active[i]->target));
        }
        return success;
    }
    bool HasActiveInlineHookEntries(){
        const std::lock_guard<std::recursive_mutex> lock(g_engineMutex);
        return std::any_of(g_activeEntries.begin(),g_activeEntries.end(),[](const auto& entry){return !entry.second->pending;});
    }

    bool IsNativeRuntimeHookTarget(void* exportAddress)
    {
        ScopedInlineHookInternalBypass bypass;
        const std::lock_guard<std::recursive_mutex> lock(g_engineMutex);
        std::size_t offset = 0;
        const wchar_t* reason = nullptr;
        void* target = ResolveJumpStub(exportAddress, &offset, &reason);
        HMODULE owner = nullptr;
        return target && ::GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCWSTR>(target), &owner) && owner == ::GetModuleHandleW(L"ntdll.dll");
    }

    InlineHookInstallResult InstallInlineHookAtAddress(void* exportAddress, void* detourAddress,
        InlineHookRecord* hookOut, void** originalOut, std::wstring* errorTextOut)
    {
        APIMON_DIAG_ADD(InstallCalls,1);
        APIMON_DIAG_SCOPE(InstallTicks);
        ScopedInlineHookInternalBypass bypass;
        const std::lock_guard<std::recursive_mutex> lock(g_engineMutex);
        if (errorTextOut) errorTextOut->clear();
        auto fail = [&](const wchar_t* reason, void* address, std::size_t offset, bool permanent) {
            wchar_t diagnostic[384]{};
            swprintf_s(diagnostic, L"address=%p offset=%zu: %s", address, offset, reason);
            if (errorTextOut) *errorTextOut = diagnostic;
            if (hookOut) { hookOut->lastFailure = diagnostic; hookOut->failureOffset = offset;
                hookOut->permanentlyDisabled = permanent; }
            return permanent ? InlineHookInstallResult::PermanentFailure : InlineHookInstallResult::RetryableFailure;
        };
        if (!exportAddress || !detourAddress || !hookOut || !originalOut)
            return fail(L"invalid hook argument", exportAddress, 0, true);
        if (HookInstallationCancelled()) return fail(L"installation cancelled",exportAddress,0,false);
        if (hookOut->installed) { *originalOut = hookOut->trampolineAddress; return InlineHookInstallResult::Installed; }
        hookOut->removed = false;
        if (hookOut->permanentlyDisabled) return fail(L"previous unsafe installation rejected", exportAddress, hookOut->failureOffset, true);
        std::size_t failureOffset = 0;
        const wchar_t* reason = nullptr;
        auto* entry = static_cast<unsigned char*>(ResolveJumpStub(exportAddress, &failureOffset, &reason));
        if (!entry) return fail(reason, exportAddress, failureOffset, true);
        unsigned char saved[32]{};
        auto readable = ReadCode(entry, saved, sizeof(saved));
        if (!readable) return fail(L"unreadable entry", entry, 0, true);
        const bool endbr = readable >= 4 && std::memcmp(saved, kLandingPad, 4) == 0;
        auto* target = entry + (endbr ? 4 : 0);
        // Check already-patched addresses before decoding or following the installed detour.
        if (auto* p = FindPatchContaining(reinterpret_cast<std::uintptr_t>(target)))
        {
            if (target != p->target || detourAddress != p->detour)
                return fail(L"patch interval conflicts with an incompatible handler", target, 0, true);
            if(p->pending&&g_pendingBatch&&g_pendingBatch->references.size()==g_pendingBatch->references.capacity())
                g_pendingBatch->references.reserve((std::max)(std::size_t{64},g_pendingBatch->references.capacity()*2));
            ++p->references;
            hookOut->targetAddress = target; hookOut->detourAddress = detourAddress;
            hookOut->trampolineAddress = p->trampoline; hookOut->patchSize = p->size;
            hookOut->originalBytes = p->original; hookOut->sharedPatchContext = p;
            hookOut->installed = true; hookOut->sharedEntry = true; hookOut->lastFailure.clear();
            *originalOut = p->trampoline;
            if(p->pending&&g_pendingBatch)g_pendingBatch->references.push_back({p,hookOut});
            return InlineHookInstallResult::Installed;
        }
        unsigned char* allocation = AllocateNear(target);
        if(HookInstallationCancelled()){
            if(allocation)detail::ReleaseCodePage(allocation);
            return fail(L"installation cancelled",target,0,false);
        }
        const bool usesNearRelay = allocation != nullptr;
        if (!allocation) allocation = static_cast<unsigned char*>(::VirtualAlloc(nullptr, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
        if (!allocation) return fail(L"trampoline allocation failed", target, 0, false);
        const std::size_t prefix = endbr ? 4 : 0;
        std::memmove(saved, saved + prefix, readable - prefix); readable -= prefix;
        std::vector<InstructionDescription> instructions;
        instructions.reserve(32);
        const std::size_t required = usesNearRelay ? 5 : kAbsoluteJumpSize;
        const auto patchSize = CalculatePatchSize(saved, readable, required, &instructions, &failureOffset, &reason);
        if (!patchSize)
        { detail::ReleaseCodePage(allocation); return fail(reason, target, failureOffset, true); }
        const auto following = g_activeEntries.lower_bound(reinterpret_cast<std::uintptr_t>(target));
        if (following != g_activeEntries.end() && following->first - reinterpret_cast<std::uintptr_t>(target) < patchSize)
        { detail::ReleaseCodePage(allocation); return fail(L"overlapping patch interval", target, 0, true); }
        if (endbr) std::memcpy(allocation, kLandingPad, 4);
        std::size_t emitted = 0;
        if (!BuildRelocatedCode(saved, reinterpret_cast<std::uintptr_t>(target), patchSize,
            allocation + prefix, reinterpret_cast<std::uintptr_t>(allocation + prefix), instructions,
            &emitted, &failureOffset, &reason))
        { detail::ReleaseCodePage(allocation); return fail(reason, target, failureOffset, true); }
        // Prefer direct return control flow when usesNearRelay; no register is clobbered.
        auto* tail = allocation + prefix + emitted;
        const auto returnDelta = static_cast<std::int64_t>(reinterpret_cast<std::uintptr_t>(target + patchSize))
            - static_cast<std::int64_t>(reinterpret_cast<std::uintptr_t>(tail + 5));
        if (FitsRel32(returnDelta))
        { tail[0] = 0xE9; const std::int32_t delta = static_cast<std::int32_t>(returnDelta); std::memcpy(tail + 1, &delta, 4); }
        else BuildAbsoluteJump(tail, target + patchSize);
        constexpr std::size_t relayOffset = 1024;
        BuildAbsoluteJump(allocation + relayOffset, detourAddress);
        auto state = std::make_unique<EntryPatch>();
        state->target = target; state->detour = detourAddress; state->trampoline = allocation; state->size = patchSize;
        std::memcpy(state->original.data(), saved, patchSize);
        std::memset(state->patched.data(), 0x90, patchSize);
        if (usesNearRelay)
        {
            const auto delta = static_cast<std::int64_t>(reinterpret_cast<std::uintptr_t>(allocation + relayOffset))
                - static_cast<std::int64_t>(reinterpret_cast<std::uintptr_t>(target + 5));
            if (!FitsRel32(delta)) { detail::ReleaseCodePage(allocation); return fail(L"usesNearRelay relay exceeds rel32 range", target, 0, false); }
            state->patched[0] = 0xE9; const auto relative = static_cast<std::int32_t>(delta);
            std::memcpy(state->patched.data() + 1, &relative, 4);
        }
        else BuildAbsoluteJump(state->patched.data(), detourAddress);
        MEMORY_BASIC_INFORMATION image{};
        if (!::VirtualQuery(target, &image, sizeof(image)))
        { detail::ReleaseCodePage(allocation); return fail(L"could not verify target allocation", target, 0, false); }
        if (image.Type == MEM_IMAGE)
        {
            HMODULE pinned = nullptr;
            if (!::GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
                reinterpret_cast<LPCWSTR>(target), &pinned))
            { detail::ReleaseCodePage(allocation); return fail(L"could not pin target image", target, 0, false); }
        }
        DWORD ignored = 0;
        if (!::VirtualProtect(allocation, 4096, PAGE_EXECUTE_READ, &ignored))
        { detail::ReleaseCodePage(allocation); return fail(L"could not seal executable trampoline", target, 0, false); }
        ::FlushInstructionCache(::GetCurrentProcess(), allocation, 4096);
        // Allocate the tree node before freezing; insertion below cannot take
        // the heap lock of a suspended application thread.
        std::map<std::uintptr_t,EntryPatch*> preparedIndex;
        preparedIndex.emplace(reinterpret_cast<std::uintptr_t>(target),state.get());
        auto indexNode=preparedIndex.extract(preparedIndex.begin());
        if(g_entryPatches.size()==g_entryPatches.capacity())g_entryPatches.reserve((std::max)(std::size_t{64},g_entryPatches.capacity()*2));
        if(g_pendingBatch){
            if(g_pendingBatch->entries.size()==g_pendingBatch->entries.capacity())
                g_pendingBatch->entries.reserve((std::max)(std::size_t{64},g_pendingBatch->entries.capacity()*2));
            if(g_pendingBatch->references.size()==g_pendingBatch->references.capacity())
                g_pendingBatch->references.reserve((std::max)(std::size_t{64},g_pendingBatch->references.capacity()*2));
            state->references=1;state->active=true;state->pending=true;
            hookOut->targetAddress=target;hookOut->detourAddress=detourAddress;
            hookOut->trampolineAddress=allocation;hookOut->patchSize=patchSize;
            hookOut->originalBytes=state->original;hookOut->sharedPatchContext=state.get();
            hookOut->installed=true;hookOut->sharedEntry=false;hookOut->lastFailure.clear();*originalOut=allocation;
            auto* context=state.get();g_entryPatches.push_back(std::move(state));
            g_activeEntries.insert(std::move(indexNode));
            g_pendingBatch->entries.push_back(context);g_pendingBatch->references.push_back({context,hookOut});
            return InlineHookInstallResult::Installed;
        }
        DWORD oldProtect = 0;
        if (!::VirtualProtect(target, patchSize, PAGE_EXECUTE_READWRITE, &oldProtect))
        { detail::ReleaseCodePage(allocation); return fail(L"target protection failed", target, 0, false); }
        ScopedOtherThreadsSuspender suspended;
        unsigned char currentBytes[32]{};
        if (!suspended.FailureText().empty())
        {
            suspended.Resume();
            const std::wstring diagnostic = suspended.FailureText();
            ::VirtualProtect(target, patchSize, oldProtect, &ignored);
            detail::ReleaseCodePage(allocation);
            return fail(diagnostic.c_str(), target, 0, false);
        }
        if (!suspended.CanPatch(target, patchSize))
        {
            suspended.Resume();
            const std::wstring diagnostic = suspended.FailureText().empty()
                ? std::wstring(L"thread context could not be verified")
                : suspended.FailureText();
            ::VirtualProtect(target, patchSize, oldProtect, &ignored);
            detail::ReleaseCodePage(allocation);
            return fail(diagnostic.c_str(), target, 0, false);
        }
        if (!SafeRead(target, currentBytes, patchSize))
        {
            suspended.Resume();
            ::VirtualProtect(target, patchSize, oldProtect, &ignored);
            detail::ReleaseCodePage(allocation);
            return fail(L"target unreadable while threads were suspended", target, 0, false);
        }
        if (std::memcmp(currentBytes, saved, patchSize) != 0)
        {
            suspended.Resume();
            ::VirtualProtect(target, patchSize, oldProtect, &ignored);
            detail::ReleaseCodePage(allocation);
            return fail(L"entry changed while preparing patch", target, 0, false);
        }
        hookOut->targetAddress = target; hookOut->detourAddress = detourAddress;
        hookOut->trampolineAddress = allocation; hookOut->patchSize = patchSize;
        hookOut->originalBytes = state->original; hookOut->sharedPatchContext = state.get();
        hookOut->sharedEntry = false; *originalOut = allocation;
        std::memcpy(target, state->patched.data(), patchSize);
        ::FlushInstructionCache(::GetCurrentProcess(), target, patchSize);
        ::VirtualProtect(target, patchSize, oldProtect, &ignored);
        hookOut->installed = true; state->references = 1; state->active = true;
        g_entryPatches.push_back(std::move(state)); // reserved before suspension
        g_activeEntries.insert(std::move(indexNode));
        suspended.Resume();
        hookOut->lastFailure.clear();
        return InlineHookInstallResult::Installed;
    }

    InlineHookInstallResult InstallInlineHook(const wchar_t* moduleName, const char* procName,
        void* detourAddress, InlineHookRecord* hookOut, void** originalOut, std::wstring* errorTextOut)
    {
        ScopedInlineHookInternalBypass bypass;
        if (!moduleName || !procName || !hookOut || !originalOut || !detourAddress)
        {
            if (errorTextOut) *errorTextOut = L"invalid hook argument";
            return InlineHookInstallResult::PermanentFailure;
        }
        if (hookOut->installed) return InlineHookInstallResult::Installed;
        hookOut->removed = false;
        const auto module = ::GetModuleHandleW(moduleName);
        if (!module)
        {
            hookOut->lastFailure = std::wstring(L"module not loaded: ") + moduleName;
            if (errorTextOut) *errorTextOut = hookOut->lastFailure;
            return InlineHookInstallResult::RetryableFailure;
        }
        auto* entry = reinterpret_cast<void*>(::GetProcAddress(module, procName));
        if (!entry)
        {
            hookOut->permanentlyDisabled = true;
            hookOut->lastFailure = L"export unavailable";
            if (errorTextOut) *errorTextOut = hookOut->lastFailure;
            return InlineHookInstallResult::PermanentFailure;
        }
        return InstallInlineHookAtAddress(entry, detourAddress, hookOut, originalOut, errorTextOut);
    }

    bool UninstallInlineHook(InlineHookRecord* hook)
    {
        ScopedInlineHookInternalBypass bypass;
        const std::lock_guard<std::recursive_mutex> lock(g_engineMutex);
        if (!hook || !hook->installed) return true;
        auto* state = static_cast<EntryPatch*>(hook->sharedPatchContext);
        if(state&&!state->active&&state->bulkRestored){hook->installed=false;hook->removed=true;hook->lastFailure.clear();return true;}
        if (!state || !state->active || !state->references) return false;
        if (state->references > 1) { --state->references; hook->installed = false; hook->removed = true; return true; }
        DWORD oldProtect = 0, ignored = 0;
        if (!::VirtualProtect(state->target, state->size, PAGE_EXECUTE_READWRITE, &oldProtect))
        { hook->lastFailure = L"target protection failed during removal; retry required"; return false; }
        ScopedOtherThreadsSuspender suspended;
        unsigned char currentBytes[32]{};
        if (!suspended.CanPatch(state->target, state->size) || !SafeRead(state->target, currentBytes, state->size)
            || std::memcmp(currentBytes, state->patched.data(), state->size) != 0)
        {
            suspended.Resume();
            ::VirtualProtect(state->target, state->size, oldProtect, &ignored);
            hook->lastFailure = L"entry modified or thread context unsafe during removal; retry required";
            return false;
        }
        std::memcpy(state->target, state->original.data(), state->size);
        ::FlushInstructionCache(::GetCurrentProcess(), state->target, state->size);
        ::VirtualProtect(state->target, state->size, oldProtect, &ignored);
        hook->installed = false; hook->removed = true; state->references = 0; state->active = false;
        suspended.Resume();
        g_activeEntries.erase(reinterpret_cast<std::uintptr_t>(state->target));
        hook->lastFailure.clear();
        // The immutable executable allocation, original pointers and registry context remain live.
        return true;
    }
}
