#pragma once

// Bounded, metadata-independent RAW code planning. ReadFn only inspects an
// owner's current cache; the owner performs asynchronous I/O after NeedData.
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace ks::ui::detail
{
    class RawCodePlanner final
    {
    public:
        struct Config
        {
            std::uint64_t entryAddress = 0;
            std::uint64_t selectedAddress = 0;
            std::uint64_t firstAddress = 0;
            std::uint64_t lastAddress = UINT64_MAX; // Inclusive, including address zero.
            bool x64 = true;
            std::size_t maximumPages = 256;
            std::size_t maximumCapturedBytes = 1024 * 1024;
            std::size_t maximumInstructions = 4096;
            std::size_t maximumCodeBytes = 64 * 1024;
        };
        struct Page
        {
            bool ok = false;
            std::uint64_t address = 0;
            std::vector<std::uint8_t> bytes;
            std::vector<std::uint8_t> validMask; // 1=known, 0=unreadable, 2=pending.
        };
        struct Segment
        {
            std::uint64_t address = 0;
            std::vector<std::uint8_t> bytes;
        };
        struct AddressRange
        {
            std::uint64_t address = 0;
            std::uint64_t length = 0;
        };
        enum class Status { NeedData, Yield, Complete, Error };
        struct StepResult
        {
            Status status = Status::Yield;
            std::uint64_t address = 0; // Needed range or first error address.
            std::uint64_t length = 0;
            std::string error;         // Stable machine code, translated by the UI.
        };
        using ReadFn = std::function<Page(std::uint64_t, std::uint64_t)>;

        explicit RawCodePlanner(const Config& config);
        ~RawCodePlanner();
        RawCodePlanner(RawCodePlanner&&) noexcept;
        RawCodePlanner& operator=(RawCodePlanner&&) noexcept;
        RawCodePlanner(const RawCodePlanner&) = delete;
        RawCodePlanner& operator=(const RawCodePlanner&) = delete;

        StepResult advance(const ReadFn& read, std::size_t maximumInstructionsThisTurn = 128);
        const std::vector<Segment>& segments() const;
        const std::vector<AddressRange>& bodyRanges() const;
        std::size_t instructionCount() const noexcept;
        std::size_t capturedByteCount() const noexcept;
        const std::string& error() const noexcept;

    private:
        struct Impl;
        std::unique_ptr<Impl> impl_;
    };
}
