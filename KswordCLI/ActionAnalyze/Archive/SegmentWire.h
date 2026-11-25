#pragma once

#include "SegmentFormat.h"

namespace ks::cli::action_analyze::archive::wire {

inline constexpr std::array<std::uint8_t, 8> kSegmentMagic{{'K', 'S', 'A', 'A', 'S', 'E', 'G', 0}};
inline constexpr std::array<std::uint8_t, 4> kBlockMagic{{'A', 'A', 'B', '1'}};
inline constexpr std::uint16_t kSegmentMajor = 1;
inline constexpr std::uint16_t kSegmentMinor = 0;
inline constexpr std::uint16_t kBlockVersion = 1;
inline constexpr std::uint16_t kStoredCodec = 0;
inline constexpr std::uint16_t kQpcValid = 1;

// 使用独立的字节读写避免宿主端序、对齐和结构体填充影响格式。
template <typename T>
T Get(const std::uint8_t* bytes, std::size_t offset) noexcept
{
    std::uint64_t result = 0;
    for (std::size_t i = 0; i < sizeof(T); ++i) {
        result |= static_cast<std::uint64_t>(bytes[offset + i]) << (8 * i);
    }
    return static_cast<T>(result);
}

template <typename T>
void Put(std::uint8_t* bytes, std::size_t offset, T value) noexcept
{
    for (std::size_t i = 0; i < sizeof(T); ++i) {
        bytes[offset + i] = static_cast<std::uint8_t>(static_cast<std::uint64_t>(value) >> (8 * i));
    }
}

inline bool KnownStream(StreamKind kind) noexcept
{
    switch (kind) {
    case StreamKind::Raw:
    case StreamKind::Records:
    case StreamKind::Control:
    case StreamKind::Analysis:
        return true;
    }
    return false;
}

inline bool IsCatalogTypeV1(std::uint16_t type, std::uint16_t version) noexcept
{
    // 对应存储设计第 4.3 节记录目录。具体 payload 校验由各消费方负责。
    return type >= 1 && type <= 22 && version == 1;
}

} // namespace ks::cli::action_analyze::archive::wire
