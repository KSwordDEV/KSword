// Standalone production planner regression. Synthetic bytes are never executed.
#include "../Ksword5.1/Ksword5.1/UI/Decompiler/RawCodePlanner.h"
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <limits>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace
{
    using Planner = ks::ui::detail::RawCodePlanner;
    unsigned checks = 0;
    unsigned failures = 0;
    void require(const bool ok, const char* text)
    {
        ++checks;
        if (!ok) { ++failures; std::printf("FAIL %u: %s\n", checks, text); }
    }

    struct Memory
    {
        std::uint64_t base;
        std::vector<std::uint8_t> bytes;
        std::vector<std::uint8_t> mask;
        std::set<std::uint64_t> pending;
        std::set<std::uint64_t> unavailable;
        std::map<std::uint64_t, unsigned> calls;
        bool malformed = false;
        explicit Memory(std::size_t size, std::uint64_t address = 0x100000)
            : base(address), bytes(size, 0xcc), mask(size, 1) {}
        void put(std::size_t at, const std::vector<std::uint8_t>& data)
        {
            std::copy(data.begin(), data.end(), bytes.begin() + at);
        }
        void hole(std::size_t at, std::size_t length)
        {
            std::fill(mask.begin() + at, mask.begin() + at + length, std::uint8_t{0});
        }
        Planner::Config config(std::size_t entry = 0, std::size_t selected = 0, bool x64 = true) const
        {
            Planner::Config value;
            value.entryAddress = base + entry;
            value.selectedAddress = base + selected;
            value.firstAddress = base;
            value.lastAddress = base + bytes.size() - 1;
            value.x64 = x64;
            return value;
        }
        Planner::Page read(std::uint64_t address, std::uint64_t length)
        {
            ++calls[address];
            Planner::Page page;
            page.address = address;
            if (unavailable.count(address)) return page;
            if (address < base || address - base >= bytes.size() || length > bytes.size() - (address - base)) return page;
            const auto offset = static_cast<std::size_t>(address - base);
            page.ok = true;
            page.bytes.assign(bytes.begin() + offset, bytes.begin() + offset + static_cast<std::size_t>(length));
            page.validMask.assign(mask.begin() + offset, mask.begin() + offset + static_cast<std::size_t>(length));
            if (pending.count(address)) std::fill(page.validMask.begin(), page.validMask.end(), std::uint8_t{2});
            if (malformed && !page.validMask.empty()) page.validMask.pop_back();
            return page;
        }
    };

    std::vector<std::uint8_t> hex(const char* text)
    {
        std::vector<std::uint8_t> result;
        while (*text)
        {
            const auto digit = [](char c) { return c <= '9' ? c - '0' : c - 'a' + 10; };
            const unsigned high = static_cast<unsigned>(digit(*text++));
            const unsigned low = static_cast<unsigned>(digit(*text++));
            result.push_back(static_cast<std::uint8_t>(high * 16 + low));
        }
        return result;
    }

    Planner::StepResult step(Planner& planner, Memory& memory, std::size_t limit = 128)
    {
        return planner.advance([&](auto address, auto length) { return memory.read(address, length); }, limit);
    }
    Planner::StepResult finish(Planner& planner, Memory& memory, std::size_t limit = 128)
    {
        for (unsigned i = 0; i < 10000; ++i)
        {
            auto value = step(planner, memory, limit);
            if (value.status != Planner::Status::Yield) return value;
        }
        require(false, "planner yields only a bounded number of turns");
        return {};
    }
    std::uint64_t bodyBytes(const Planner& planner)
    {
        std::uint64_t length = 0;
        for (const auto& range : planner.bodyRanges()) length += range.length;
        return length;
    }
    bool covers(const Planner& planner, std::uint64_t address, std::uint64_t length)
    {
        for (const auto& range : planner.bodyRanges())
            if (address >= range.address && address - range.address <= range.length
                && length <= range.length - (address - range.address)) return true;
        return false;
    }
    void successful(Planner& planner, Memory& memory, std::uint64_t codeBytes, const char* name)
    {
        const auto result = finish(planner, memory);
        if (result.status != Planner::Status::Complete)
            std::printf("case %s ended error=%s at=%llx\n", name, result.error.c_str(), static_cast<unsigned long long>(result.address));
        require(result.status == Planner::Status::Complete, name);
        require(bodyBytes(planner) == codeBytes, "only reachable instruction bytes enter the function body");
        require(planner.error().empty(), "complete plans retain no stale failure");
        std::size_t captured = 0;
        for (const auto& segment : planner.segments())
        {
            captured += segment.bytes.size();
            for (std::size_t i = 0; i < segment.bytes.size(); ++i)
            {
                const auto offset = static_cast<std::size_t>(segment.address + i - memory.base);
                require(memory.mask[offset] == 1, "no unavailable placeholder byte is exported");
                require(segment.bytes[i] == memory.bytes[offset], "exported snapshot bytes equal the captured source");
            }
        }
        require(captured == planner.capturedByteCount(), "captured count matches complete sparse evidence");
    }
    void rejected(Planner& planner, Memory& memory, const char* code, const char* name)
    {
        const auto result = finish(planner, memory);
        require(result.status == Planner::Status::Error && result.error == code, name);
        const auto again = step(planner, memory);
        require(again.status == Planner::Status::Error && again.error == result.error && again.address == result.address,
            "an errored plan is terminal and cannot silently restart");
    }

    void anonymousFixtures()
    {
        {
            Memory memory(4096); memory.put(0, hex("b82a000000c3"));
            Planner planner(memory.config(0, 3)); successful(planner, memory, 6, "ordinary RAW function and selected operand byte");
            require(planner.instructionCount() == 2, "MOV and RET are counted exactly once");
        }
        {
            Memory memory(4096); memory.put(0, hex("85c974087809b801000000c331c0c3b8ffffffffc3"));
            Planner planner(memory.config(0, 12)); successful(planner, memory, 21, "multiple branches and multiple returns");
            require(planner.instructionCount() == 9, "joined worklists do not duplicate decoded instructions");
        }
        {
            Memory memory(3 * 4096); memory.put(0, hex("85c90f84f8200000b801000000c3"));
            memory.put(0x2100, hex("b82a000000c3")); memory.hole(4096, 4096);
            Planner planner(memory.config(0, 8)); successful(planner, memory, 20, "direct branch beyond initial 4 KiB");
            require(covers(planner, memory.base + 0x2100, 6), "far branch target is genuinely included in the body");
            require(!memory.calls.count(memory.base + 4096), "an unrelated intervening hole is never requested");
            require(planner.bodyRanges().size() == 2, "discontiguous function regions remain discontiguous");
        }
        {
            Memory memory(4 * 4096); memory.put(0, hex("8b05fa2f000085c90f85f2100000c3"));
            memory.put(0x1100, hex("83c007c3")); memory.put(0x3000, hex("78563412")); memory.hole(0x2000, 4096);
            Planner planner(memory.config(0, 6)); successful(planner, memory, 19, "separate code regions and RIP constant");
            require(memory.calls.count(memory.base + 0x3000) == 1, "static RIP-read data page is captured");
            require(!memory.calls.count(memory.base + 0x2000), "unreferenced NOACCESS page is not needed");
            require(!covers(planner, memory.base + 0x3000, 1), "read-only constants are not relabeled as code");
        }
        {
            Memory memory(2 * 4096); memory.put(0, hex("e8fb10000083c003c3")); memory.put(0x1100, hex("b807000000c3"));
            Planner planner(memory.config(0, 5)); successful(planner, memory, 9, "ordinary direct call does not recurse into callee");
            require(!memory.calls.count(memory.base + 4096), "callee-only page is not captured");
        }
        {
            Memory memory(3 * 4096); memory.put(0, hex("e9fb1f0000")); memory.put(0x2000, hex("b82a000000c3")); memory.hole(4096, 4096);
            Planner planner(memory.config()); successful(planner, memory, 11, "branch across unreadable or guard page");
            require(!memory.calls.count(memory.base + 4096), "guard page is never requested by a spanning window");
        }
        {
            Memory memory(3 * 4096); memory.put(0, hex("85c90f84f80f0000b801000000c3")); memory.hole(4096, 4096);
            Planner planner(memory.config(0, 8)); rejected(planner, memory, "snapshot_unreadable", "unreadable direct target is not accepted as a complete body");
        }
        {
            Memory memory(2 * 4096); memory.put(4094, hex("b82a000000c3"));
            Planner planner(memory.config(4094, 4099)); successful(planner, memory, 6, "instruction spanning two pages");
            require(planner.instructionCount() == 2 && memory.calls.size() == 2, "cross-page MOV and RET are complete with two pages");
        }
    }

    void architectureAndFlow()
    {
        {
            Memory memory(4096, 0xff000000); memory.put(0, hex("558bec8b450803450c5dc3"));
            Planner planner(memory.config(0, 8, false)); successful(planner, memory, 11, "x86 stack-argument code at a high address");
        }
        {
            Memory memory(1, UINT64_MAX); memory.put(0, hex("c3"));
            Planner planner(memory.config()); successful(planner, memory, 1, "x64 RET at final representable address");
        }
        {
            Memory memory(1, UINT32_MAX); memory.put(0, hex("c3"));
            Planner planner(memory.config(0, 0, false)); successful(planner, memory, 1, "x86 RET at final 32-bit address");
        }
        {
            Memory memory(4096, 0); memory.put(0, hex("ebfd"));
            Planner planner(memory.config()); rejected(planner, memory, "incomplete_control_flow", "relative branch underflow cannot wrap");
        }
        {
            Memory memory(3, UINT64_MAX - 2); memory.put(0, hex("eb7f"));
            Planner planner(memory.config()); rejected(planner, memory, "incomplete_control_flow", "relative branch overflow cannot wrap");
        }
        {
            Memory memory(4096); memory.put(0, hex("7501b8c3000000c3"));
            Planner planner(memory.config()); rejected(planner, memory, "invalid_instruction_data", "branch into another instruction is rejected");
        }
        {
            Memory memory(4096); memory.put(0, hex("ffe0"));
            Planner planner(memory.config()); rejected(planner, memory, "incomplete_control_flow", "unknown indirect jump remains incomplete");
        }
        {
            Memory memory(4096); memory.put(0, hex("ffd0c3"));
            Planner planner(memory.config()); successful(planner, memory, 3, "ordinary indirect call retains caller continuation");
        }
        {
            Memory memory(4096); memory.put(0, hex("488d05f92f0000c3"));
            Planner planner(memory.config()); successful(planner, memory, 8, "LEA computes an address without reading its bytes");
        }
        {
            Memory memory(4096); memory.put(0, hex("8b05fa2f0000c3"));
            Planner planner(memory.config()); rejected(planner, memory, "snapshot_unreadable", "static memory read outside allowed range fails honestly");
        }
        {
            Memory memory(2 * 4096, 0x1000); memory.put(0, hex("a100200000c3"));
            Planner planner(memory.config(0, 0, false)); successful(planner, memory, 6, "x86 absolute-address data reference");
            require(memory.calls.count(0x2000) == 1, "x86 absolute data page was requested");
        }
        {
            Memory memory(4096); memory.put(0, hex("65488b042530000000c3"));
            Planner planner(memory.config()); successful(planner, memory, 10, "GS segment address does not become a false absolute read");
            require(memory.calls.size() == 1, "unknown GS base is not guessed");
        }
        {
            Memory memory(2 * 4096, 0x1000); memory.put(0, hex("488b05f50f0000c3"));
            Planner planner(memory.config()); successful(planner, memory, 8, "static qword data access spanning pages");
            require(memory.calls.count(0x2000) == 1, "entire referenced qword is captured rather than only its first byte");
        }
        {
            Memory memory(2 * 4096, 0x100001000ULL); memory.put(0, hex("678b05f90f0000c3"));
            Planner planner(memory.config()); rejected(planner, memory, "snapshot_unreadable", "EIP-relative addressing in x64 uses the 32-bit instruction pointer");
            require(!memory.calls.count(memory.base + 4096), "EIP data reference cannot be mistaken for a high-VA RIP reference");
        }
        {
            Memory memory(9, UINT64_MAX - 8); memory.put(0, hex("8b0510000000c3"));
            Planner planner(memory.config()); rejected(planner, memory, "snapshot_unreadable", "overflowing RIP-relative data address is not silently ignored");
        }
        {
            Memory memory(4096, 0); memory.put(1, hex("8b05f0ffffffc3"));
            Planner planner(memory.config(1, 1)); rejected(planner, memory, "snapshot_unreadable", "underflowing RIP-relative data address is not silently ignored");
        }
    }

    void lifecycleAndBudgets()
    {
        {
            Memory memory(3 * 4096); memory.put(0, hex("85c90f84f8200000b801000000c3")); memory.put(0x2100, hex("b82a000000c3"));
            memory.pending.insert(memory.base + 0x2000);
            Planner planner(memory.config(0, 8));
            auto result = finish(planner, memory);
            const auto before = planner.instructionCount();
            require(result.status == Planner::Status::NeedData && result.address == memory.base + 0x2000 && result.length == 4096,
                "far pending page returns its exact host read request");
            result = step(planner, memory);
            require(result.status == Planner::Status::NeedData && planner.instructionCount() == before,
                "repeated pending calls preserve instruction counters and worklists");
            memory.pending.clear();
            successful(planner, memory, 20, "pending capture resumes same plan without resetting its entry");
            require(memory.calls[memory.base] == 1, "already frozen pages are not refetched after asynchronous progress");
        }
        {
            Memory memory(4096); memory.put(0, hex("c3")); memory.unavailable.insert(memory.base);
            Planner planner(memory.config()); require(step(planner, memory).status == Planner::Status::NeedData, "ok=false is a host read request");
            memory.unavailable.clear(); successful(planner, memory, 1, "ok=false read can later settle");
        }
        {
            Memory memory(4096); memory.put(0, hex("9090c3"));
            Planner planner(memory.config());
            require(step(planner, memory, 1).status == Planner::Status::Yield && planner.instructionCount() == 1,
                "per-turn instruction budget yields to the UI");
            require(finish(planner, memory, 1).status == Planner::Status::Complete && planner.instructionCount() == 3,
                "yielding does not restart the plan");
        }
        {
            Memory memory(4096); memory.put(0, hex("c3")); memory.hole(1, 4095);
            Planner planner(memory.config()); successful(planner, memory, 1, "unreadable padding does not invalidate an already complete RET");
            require(planner.segments().size() == 1 && planner.segments()[0].bytes.size() == 1,
                "sparse evidence excludes all unreadable padding");
        }
        {
            Memory memory(1); memory.put(0, hex("0f"));
            Planner planner(memory.config()); rejected(planner, memory, "invalid_instruction_data", "incomplete last instruction cannot use invented trailing zeros");
        }
        {
            Memory memory(4096); memory.put(0, hex("c3")); memory.malformed = true;
            Planner planner(memory.config()); rejected(planner, memory, "snapshot_unreadable", "mismatched bytes and mask lengths fail");
        }
        {
            Memory memory(4096); memory.put(0, hex("c3")); memory.mask[7] = 3;
            Planner planner(memory.config()); rejected(planner, memory, "snapshot_unreadable", "unknown availability masks fail");
        }
        {
            Memory memory(3 * 4096); memory.put(0, hex("e9fb1f0000")); memory.put(0x2000, hex("c3"));
            auto config = memory.config(); config.maximumPages = 1;
            Planner planner(config); rejected(planner, memory, "analysis_budget_exceeded", "page budget stops remote branch expansion");
        }
        {
            Memory memory(4096); memory.put(0, hex("c3")); auto config = memory.config(); config.maximumCapturedBytes = 4095;
            Planner planner(config); rejected(planner, memory, "analysis_budget_exceeded", "captured evidence bytes obey a hard budget");
        }
        {
            Memory memory(4096); memory.put(0, hex("9090c3")); auto config = memory.config(); config.maximumInstructions = 2;
            Planner planner(config); rejected(planner, memory, "analysis_budget_exceeded", "instruction count cannot silently truncate a function");
        }
        {
            Memory memory(4096); memory.put(0, hex("b82a000000c3")); auto config = memory.config(); config.maximumCodeBytes = 4;
            Planner planner(config); rejected(planner, memory, "analysis_budget_exceeded", "code-byte budget cannot split an instruction");
        }
        {
            Memory memory(4096); memory.put(0, hex("c3"));
            Planner planner(memory.config(0, 20)); rejected(planner, memory, "selected_outside_function", "selected data beyond a RET is not called the same function");
        }
        {
            Memory memory(4096); memory.put(0, hex("c3")); auto config = memory.config(); config.entryAddress = memory.base - 1;
            Planner planner(config); rejected(planner, memory, "invalid_address", "candidate entry must belong to the explicit capture address scope");
        }
        {
            Memory memory(4096); memory.put(0, hex("c3")); auto config = memory.config(); config.maximumPages = 0;
            Planner planner(config); rejected(planner, memory, "analysis_budget_exceeded", "zero resource budgets cannot start unrestricted work");
        }
        {
            Memory memory(4096); memory.put(0, hex("c3")); memory.pending.insert(memory.base);
            { Planner old(memory.config()); require(step(old, memory).status == Planner::Status::NeedData, "old pending plan can be discarded for cancellation"); }
            memory.pending.clear(); memory.put(0, hex("b807000000c3"));
            Planner fresh(memory.config()); successful(fresh, memory, 6, "new plan after cancellation captures the new source only");
        }
    }
}

int main()
{
    anonymousFixtures(); architectureAndFlow(); lifecycleAndBudgets();
    std::printf("RAW_CODE_PLANNER_CHECKS=%u FAILURES=%u\n", checks, failures);
    return failures ? EXIT_FAILURE : EXIT_SUCCESS;
}
