#include "SegmentFormat.h"

namespace ks::cli::action_analyze::archive {
namespace {

constexpr std::array<std::uint32_t, 256> MakeCrcTable() noexcept
{
    std::array<std::uint32_t, 256> table{};
    for (std::uint32_t i = 0; i < table.size(); ++i) {
        auto value = i;
        for (unsigned int bit = 0; bit < 8; ++bit) {
            value = (value >> 1) ^ ((value & 1u) != 0 ? 0x82f63b78u : 0u);
        }
        table[i] = value;
    }
    return table;
}

constexpr auto kCrcTable = MakeCrcTable();

} // namespace

std::uint32_t Crc32c(const std::uint8_t* data, std::size_t bytes) noexcept
{
    std::uint32_t crc = 0xffffffffu;
    for (std::size_t i = 0; i < bytes; ++i) {
        crc = (crc >> 8) ^ kCrcTable[(crc ^ data[i]) & 0xffu];
    }
    return crc ^ 0xffffffffu;
}

} // namespace ks::cli::action_analyze::archive
