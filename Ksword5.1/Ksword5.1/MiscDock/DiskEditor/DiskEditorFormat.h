#pragma once
#include <QString>
#include <cstdint>

namespace ks::misc::diskeditor_detail
{
    // HexOffsetText：界面与冻结读写回执共用同一 64 位偏移格式，不依赖指令架构。
    inline QString HexOffsetText(const std::uint64_t value)
    {
        return QStringLiteral("0x%1").arg(static_cast<qulonglong>(value), 16, 16, QChar('0')).toUpper();
    }
}
