#pragma once

#include "ThreadLayoutProfile.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace ks::structure_sample
{
    enum class ValueKind { Unsigned, Signed, Pointer, Boolean };
    enum class FieldStatus { Sampled, Aggregate, UnsupportedType, OutsideSnapshot, InvalidLayout };

    struct FieldValue
    {
        FieldStatus status = FieldStatus::UnsupportedType;
        ValueKind kind = ValueKind::Unsigned;
        std::uint32_t offset = 0; // 相对于已引用根对象，不是可由调用者选择的读取地址。
        std::uint32_t width = 0;
        std::uint64_t raw = 0; // 原始存储单元；位域解码不会丢弃其余原始位。
        std::uint64_t value = 0; // 位域已移位/掩码；有符号数保留二进制补码。
        std::uint32_t valueBits = 0;
        bool unionInterpretation = false; // 只解释共同存储，不宣称已判定活动分支。
        std::string path;
        std::string text;
    };

    struct Projection
    {
        bool identityMatched = false;
        std::size_t totalRows = 0; // 覆盖率分母始终包括全部符号行，含父结构和未支持类型。
        std::size_t sampledRows = 0;
        std::size_t unionRows = 0; // sampledRows 的子集，单列防止与活动分支混淆。
        std::size_t coverageRows = 0; // 验收分子：排除全部 union 解释行和重复存储描述。
        std::size_t aggregateRows = 0;
        std::size_t unsupportedRows = 0;
        std::size_t unreadRows = 0;
        std::vector<FieldValue> fields; // 与 Profile::fields 保持同序，不删除不支持的行。
    };

    // 仅解释驱动已验证且有界复制的根对象字节，不读取地址、不遍历指针。
    // 默认 availableBytes 是连续有效前缀；指定 valid 时只解码位图标记完整的字段。
    // objectSize 必须等于同身份 PDB 根类型大小，validSize 必须覆盖 availableBytes。
    Projection Project(const threadlayout::Profile& profile, const threadlayout::Identity& sampledIdentity,
        std::uint32_t objectSize, const std::uint8_t* bytes, std::size_t availableBytes,
        const std::uint8_t* valid = nullptr, std::size_t validSize = 0);

    const char* StatusName(FieldStatus status);
}
