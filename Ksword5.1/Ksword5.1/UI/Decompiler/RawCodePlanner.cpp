#include "RawCodePlanner.h"
#include <Zydis.h>

#include <algorithm>
#include <array>
#include <deque>
#include <iterator>
#include <limits>
#include <map>
#include <utility>

namespace ks::ui::detail
{
    namespace
    {
        constexpr std::uint64_t PageBytes = 4096;
        constexpr std::size_t MaximumPages = 256;
        constexpr std::size_t MaximumCapturedBytes = 1024 * 1024;
        constexpr std::size_t MaximumInstructions = 4096;
        constexpr std::size_t MaximumCodeBytes = 64 * 1024;

        bool signedAdd(std::uint64_t value, std::int64_t displacement, std::uint64_t& result)
        {
            if (displacement >= 0)
            {
                const auto delta = static_cast<std::uint64_t>(displacement);
                if (delta > UINT64_MAX - value) return false;
                result = value + delta;
            }
            else
            {
                const auto delta = static_cast<std::uint64_t>(-(displacement + 1)) + 1;
                if (delta > value) return false;
                result = value - delta;
            }
            return true;
        }
    }

    struct RawCodePlanner::Impl
    {
        struct Instruction { std::uint64_t address; std::uint8_t length; };
        struct DataNeed { std::uint64_t address; std::uint64_t length; };

        Config config;
        ZydisDecoder decoder{};
        std::map<std::uint64_t, Page> pages;
        std::map<std::uint64_t, Instruction> instructions;
        std::deque<std::uint64_t> codeQueue;
        std::deque<DataNeed> dataQueue;
        std::size_t capturedBytes = 0;
        std::size_t codeBytes = 0;
        Status status = Status::Yield;
        StepResult terminal;
        mutable bool segmentsDirty = true;
        mutable bool bodyDirty = true;
        mutable std::vector<Segment> segmentView;
        mutable std::vector<AddressRange> bodyView;

        explicit Impl(const Config& value) : config(value)
        {
            if (!config.x64) config.lastAddress = std::min<std::uint64_t>(config.lastAddress, UINT32_MAX);
            config.maximumPages = std::min(config.maximumPages, MaximumPages);
            config.maximumCapturedBytes = std::min(config.maximumCapturedBytes, MaximumCapturedBytes);
            config.maximumInstructions = std::min(config.maximumInstructions, MaximumInstructions);
            config.maximumCodeBytes = std::min(config.maximumCodeBytes, MaximumCodeBytes);
            if (config.firstAddress > config.lastAddress || !inside(config.entryAddress)
                || !inside(config.selectedAddress))
            {
                fail("invalid_address", config.entryAddress);
                return;
            }
            if (!config.maximumPages || !config.maximumCapturedBytes || !config.maximumInstructions
                || !config.maximumCodeBytes)
            {
                fail("analysis_budget_exceeded", config.entryAddress);
                return;
            }
            if (!ZYAN_SUCCESS(ZydisDecoderInit(&decoder,
                config.x64 ? ZYDIS_MACHINE_MODE_LONG_64 : ZYDIS_MACHINE_MODE_LEGACY_32,
                config.x64 ? ZYDIS_STACK_WIDTH_64 : ZYDIS_STACK_WIDTH_32)))
            {
                fail("unsupported_architecture", config.entryAddress);
                return;
            }
            codeQueue.push_back(config.entryAddress);
        }

        bool inside(const std::uint64_t address) const
        {
            return address >= config.firstAddress && address <= config.lastAddress;
        }

        StepResult fail(const char* error, const std::uint64_t address)
        {
            status = Status::Error;
            terminal = {Status::Error, address, 0, error};
            return terminal;
        }

        // A cache page is frozen only when every availability bit has settled.
        // A pending read never discards a worklist item or resets its counters.
        StepResult ensurePage(const std::uint64_t address, const ReadFn& read)
        {
            const std::uint64_t key = address & ~(PageBytes - 1);
            if (pages.find(key) != pages.end()) return {Status::Yield, 0, 0, {}};
            if (!inside(address)) return fail("snapshot_unreadable", address);
            if (pages.size() >= config.maximumPages) return fail("analysis_budget_exceeded", address);
            const auto first = std::max(key, config.firstAddress);
            const auto last = std::min(key | (PageBytes - 1), config.lastAddress);
            const auto length = last - first + 1;
            Page page;
            try
            {
                if (read) page = read(first, length);
            }
            catch (...)
            {
                return fail("snapshot_unreadable", address);
            }
            if (!page.ok) return {Status::NeedData, first, length, {}};
            if (page.address != first || page.bytes.size() != length || page.validMask.size() != length)
                return fail("snapshot_unreadable", address);
            bool pending = false;
            std::size_t known = 0;
            for (const auto mask : page.validMask)
            {
                if (mask == 1) ++known;
                else if (mask == 2) pending = true;
                else if (mask != 0) return fail("snapshot_unreadable", address);
            }
            if (pending) return {Status::NeedData, first, length, {}};
            if (known > config.maximumCapturedBytes - capturedBytes)
                return fail("analysis_budget_exceeded", address);
            capturedBytes += known;
            pages.emplace(key, std::move(page));
            segmentsDirty = true;
            return {Status::Yield, 0, 0, {}};
        }

        const Page& pageAt(const std::uint64_t address) const
        {
            return pages.at(address & ~(PageBytes - 1));
        }

        StepResult ensureData(const DataNeed& data, const ReadFn& read)
        {
            if (!data.length || !inside(data.address) || data.length - 1 > config.lastAddress - data.address)
                return fail("snapshot_unreadable", data.address);
            for (std::uint64_t offset = 0; offset < data.length;)
            {
                const auto address = data.address + offset;
                const auto state = ensurePage(address, read);
                if (state.status != Status::Yield) return state;
                const auto& page = pageAt(address);
                const auto local = static_cast<std::size_t>(address - page.address);
                const auto length = std::min<std::uint64_t>(data.length - offset, page.bytes.size() - local);
                for (std::size_t i = 0; i < static_cast<std::size_t>(length); ++i)
                    if (page.validMask[local + i] != 1) return fail("snapshot_unreadable", address + i);
                offset += length;
            }
            return {Status::Yield, 0, 0, {}};
        }

        StepResult decode(const std::uint64_t address, const ReadFn& read,
            ZydisDecodedInstruction& decoded, ZydisDecodedOperand* operands)
        {
            if (!inside(address)) return fail("incomplete_control_flow", address);
            std::array<std::uint8_t, ZYDIS_MAX_INSTRUCTION_LENGTH> bytes{};
            std::size_t available = 0;
            bool unreadable = false;
            for (;;)
            {
                if (available > config.lastAddress - address)
                    return fail("invalid_instruction_data", address);
                const auto at = address + available;
                const auto state = ensurePage(at, read);
                if (state.status != Status::Yield) return state;
                const auto& page = pageAt(at);
                const auto local = static_cast<std::size_t>(at - page.address);
                const auto count = std::min(bytes.size() - available, page.bytes.size() - local);
                for (std::size_t i = 0; i < count; ++i)
                {
                    if (page.validMask[local + i] != 1) { unreadable = true; break; }
                    bytes[available++] = page.bytes[local + i];
                }
                const ZyanStatus result = ZydisDecoderDecodeFull(&decoder, bytes.data(), available, &decoded, operands);
                if (ZYAN_SUCCESS(result))
                {
                    if (!decoded.length || decoded.length > available || decoded.length - 1 > config.lastAddress - address)
                        return fail("invalid_instruction_data", address);
                    return {Status::Yield, 0, 0, {}};
                }
                if (unreadable) return fail("snapshot_unreadable", address + available);
                if (result != ZYDIS_STATUS_NO_MORE_DATA || available == bytes.size()
                    || available > config.lastAddress - address)
                    return fail("invalid_instruction_data", address);
                // Only request the following page when this instruction actually
                // needs it; a RET at a page end does not require look-ahead bytes.
            }
        }

        bool overlap(const std::uint64_t address, const std::uint8_t length) const
        {
            auto next = instructions.lower_bound(address);
            if (next != instructions.end() && next->first - address < length) return true;
            if (next != instructions.begin())
            {
                const auto previous = std::prev(next);
                if (address - previous->first < previous->second.length) return true;
            }
            return false;
        }

        bool relativeTarget(const std::uint64_t address, const ZydisDecodedInstruction& instruction,
            const ZydisDecodedOperand* operands, std::uint64_t& target) const
        {
            if (instruction.length > UINT64_MAX - address) return false;
            for (std::size_t i = 0; i < instruction.operand_count_visible; ++i)
            {
                if (operands[i].type == ZYDIS_OPERAND_TYPE_IMMEDIATE && operands[i].imm.is_relative)
                    return signedAdd(address + instruction.length, operands[i].imm.value.s, target)
                        && inside(target);
            }
            return false;
        }

        enum class StaticTarget { Dynamic, Valid, Invalid };

        StaticTarget staticDataTarget(const std::uint64_t address, const ZydisDecodedInstruction& instruction,
            const ZydisDecodedOperand& operand, std::uint64_t& target) const
        {
            if (operand.type != ZYDIS_OPERAND_TYPE_MEMORY || operand.mem.index != ZYDIS_REGISTER_NONE
                || operand.mem.segment == ZYDIS_REGISTER_FS || operand.mem.segment == ZYDIS_REGISTER_GS)
                return StaticTarget::Dynamic;
            if (operand.mem.base == ZYDIS_REGISTER_RIP || operand.mem.base == ZYDIS_REGISTER_EIP)
            {
                if (instruction.length > UINT64_MAX - address) return StaticTarget::Invalid;
                const auto next = operand.mem.base == ZYDIS_REGISTER_EIP
                    ? (address + instruction.length) & UINT32_MAX : address + instruction.length;
                if (!signedAdd(next, operand.mem.disp.value, target)
                    || (operand.mem.base == ZYDIS_REGISTER_EIP && target > UINT32_MAX))
                    return StaticTarget::Invalid;
                return StaticTarget::Valid;
            }
            if (operand.mem.base != ZYDIS_REGISTER_NONE) return StaticTarget::Dynamic;
            return ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&instruction, &operand, address, &target))
                ? StaticTarget::Valid : StaticTarget::Invalid;
        }

        StepResult advance(const ReadFn& read, const std::size_t maximumInstructionsThisTurn)
        {
            if (status == Status::Error || status == Status::Complete) return terminal;
            std::size_t work = 0;
            const auto turnLimit = std::max<std::size_t>(1, std::min<std::size_t>(maximumInstructionsThisTurn, MaximumInstructions));
            while (work < turnLimit)
            {
                if (!dataQueue.empty())
                {
                    const auto state = ensureData(dataQueue.front(), read);
                    if (state.status != Status::Yield) return state;
                    dataQueue.pop_front();
                    ++work;
                    continue;
                }
                if (codeQueue.empty())
                {
                    auto selected = instructions.upper_bound(config.selectedAddress);
                    if (selected == instructions.begin()
                        || config.selectedAddress - std::prev(selected)->first >= std::prev(selected)->second.length)
                        return fail("selected_outside_function", config.selectedAddress);
                    status = Status::Complete;
                    terminal = {Status::Complete, 0, 0, {}};
                    return terminal;
                }
                const auto address = codeQueue.front();
                if (instructions.find(address) != instructions.end()) { codeQueue.pop_front(); continue; }
                if (instructions.size() >= config.maximumInstructions)
                    return fail("analysis_budget_exceeded", address);
                if (overlap(address, 1)) return fail("invalid_instruction_data", address);
                ZydisDecodedInstruction instruction{};
                std::array<ZydisDecodedOperand, ZYDIS_MAX_OPERAND_COUNT> operands{};
                const auto state = decode(address, read, instruction, operands.data());
                if (state.status != Status::Yield) return state;
                if (overlap(address, instruction.length)) return fail("invalid_instruction_data", address);
                if (instruction.length > config.maximumCodeBytes - codeBytes)
                    return fail("analysis_budget_exceeded", address);
                instructions.emplace(address, Instruction{address, instruction.length});
                codeQueue.pop_front();
                codeBytes += instruction.length;
                bodyDirty = true;
                ++work;
                const auto category = instruction.meta.category;
                if (instruction.mnemonic == ZYDIS_MNEMONIC_HLT || instruction.mnemonic == ZYDIS_MNEMONIC_UD2
                    || category == ZYDIS_CATEGORY_INTERRUPT)
                    return fail("incomplete_control_flow", address);

                if (instruction.mnemonic != ZYDIS_MNEMONIC_LEA)
                {
                    for (std::size_t i = 0; i < instruction.operand_count_visible; ++i)
                    {
                        const auto& operand = operands[i];
                        if (!(operand.actions & ZYDIS_OPERAND_ACTION_MASK_READ)) continue;
                        std::uint64_t target = 0;
                        const auto kind = staticDataTarget(address, instruction, operand, target);
                        if (kind == StaticTarget::Invalid) return fail("snapshot_unreadable", address);
                        if (kind == StaticTarget::Valid)
                        {
                            const auto length = std::max<std::uint64_t>(1, (operand.size + 7U) / 8U);
                            dataQueue.push_back({target, length});
                        }
                    }
                }
                if (category == ZYDIS_CATEGORY_RET || category == ZYDIS_CATEGORY_SYSRET) continue;
                if (category == ZYDIS_CATEGORY_UNCOND_BR || category == ZYDIS_CATEGORY_COND_BR)
                {
                    std::uint64_t target = 0;
                    if (!relativeTarget(address, instruction, operands.data(), target))
                        return fail("incomplete_control_flow", address);
                    codeQueue.push_back(target);
                    if (category == ZYDIS_CATEGORY_UNCOND_BR) continue;
                }
                if (instruction.length > config.lastAddress - address)
                    return fail("incomplete_control_flow", address);
                codeQueue.push_back(address + instruction.length);
            }
            return {Status::Yield, 0, 0, {}};
        }

        const std::vector<Segment>& segments() const
        {
            if (!segmentsDirty) return segmentView;
            segmentView.clear();
            for (const auto& entry : pages)
            {
                const auto& page = entry.second;
                for (std::size_t i = 0; i < page.bytes.size();)
                {
                    if (page.validMask[i] != 1) { ++i; continue; }
                    const auto first = i;
                    while (i < page.bytes.size() && page.validMask[i] == 1) ++i;
                    const auto address = page.address + first;
                    if (!segmentView.empty() && segmentView.back().bytes.size() <= UINT64_MAX - segmentView.back().address
                        && segmentView.back().address + segmentView.back().bytes.size() == address)
                        segmentView.back().bytes.insert(segmentView.back().bytes.end(), page.bytes.begin() + first, page.bytes.begin() + i);
                    else segmentView.push_back({address, {page.bytes.begin() + first, page.bytes.begin() + i}});
                }
            }
            segmentsDirty = false;
            return segmentView;
        }

        const std::vector<AddressRange>& bodyRanges() const
        {
            if (!bodyDirty) return bodyView;
            bodyView.clear();
            for (const auto& entry : instructions)
            {
                const auto& instruction = entry.second;
                if (!bodyView.empty() && bodyView.back().length <= UINT64_MAX - bodyView.back().address
                    && bodyView.back().address + bodyView.back().length == instruction.address)
                    bodyView.back().length += instruction.length;
                else bodyView.push_back({instruction.address, instruction.length});
            }
            bodyDirty = false;
            return bodyView;
        }
    };

    RawCodePlanner::RawCodePlanner(const Config& config) : impl_(std::make_unique<Impl>(config)) {}
    RawCodePlanner::~RawCodePlanner() = default;
    RawCodePlanner::RawCodePlanner(RawCodePlanner&&) noexcept = default;
    RawCodePlanner& RawCodePlanner::operator=(RawCodePlanner&&) noexcept = default;
    RawCodePlanner::StepResult RawCodePlanner::advance(const ReadFn& read, const std::size_t limit) { return impl_->advance(read, limit); }
    const std::vector<RawCodePlanner::Segment>& RawCodePlanner::segments() const { return impl_->segments(); }
    const std::vector<RawCodePlanner::AddressRange>& RawCodePlanner::bodyRanges() const { return impl_->bodyRanges(); }
    std::size_t RawCodePlanner::instructionCount() const noexcept { return impl_->instructions.size(); }
    std::size_t RawCodePlanner::capturedByteCount() const noexcept { return impl_->capturedBytes; }
    const std::string& RawCodePlanner::error() const noexcept { return impl_->terminal.error; }
}
