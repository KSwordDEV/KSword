#include "StructureSampleProjection.h"

#include <charconv>
#include <iomanip>
#include <limits>
#include <set>
#include <sstream>
#include <string_view>
#include <tuple>

namespace ks::structure_sample
{
    namespace
    {
        struct Scalar
        {
            std::uint32_t width = 0;
            ValueKind kind = ValueKind::Unsigned;
        };

        Scalar Describe(std::string_view type)
        {
            // 数组/修饰记录不推测长度；只有最终的指针本身按 amd64 指针解释。
            if (!type.empty() && type.back() == '*') return {8, ValueKind::Pointer};
            if (type.find('[') != type.npos) return {};
            if (type.substr(0, 9) == "bitfield(") type.remove_prefix(9);
            if (type.size() < 7 || type.substr(0, 2) != "0x") return {};
            const auto end = type.find(' ');
            if (end == type.npos || end < 3) return {};
            std::uint32_t code = 0;
            const auto parsed = std::from_chars(type.data() + 2, type.data() + end, code, 16);
            if (parsed.ec != std::errc{} || parsed.ptr != type.data() + end || code >= 0x1000) return {};
            // CodeView 的 simple mode 在高字节；不把旧 16/32 位指针解释为 64 位。
            const auto mode = (code >> 8) & 0xf;
            if (mode) return mode == 6 ? Scalar{8, ValueKind::Pointer} : Scalar{};
            switch (code)
            {
            case 0x10: case 0x68: case 0x70: return {1, ValueKind::Signed};
            case 0x20: case 0x69: case 0x7c: return {1, ValueKind::Unsigned};
            case 0x11: case 0x72: return {2, ValueKind::Signed};
            case 0x21: case 0x71: case 0x73: case 0x7a: return {2, ValueKind::Unsigned};
            case 0x08: case 0x12: case 0x74: return {4, ValueKind::Signed};
            case 0x22: case 0x75: case 0x7b: return {4, ValueKind::Unsigned};
            case 0x13: case 0x76: return {8, ValueKind::Signed};
            case 0x23: case 0x77: return {8, ValueKind::Unsigned};
            case 0x30: return {1, ValueKind::Boolean};
            case 0x31: return {2, ValueKind::Boolean};
            case 0x32: return {4, ValueKind::Boolean};
            case 0x33: return {8, ValueKind::Boolean};
            default: return {};
            }
        }

        std::string Format(const FieldValue& field)
        {
            std::ostringstream output;
            output << "0x" << std::hex << std::uppercase << std::setfill('0');
            if (field.kind == ValueKind::Pointer) output << std::setw(16);
            output << field.value;
            if (field.kind != ValueKind::Pointer)
            {
                output << std::dec << " (";
                const auto signBit = std::uint64_t{1} << (field.valueBits - 1);
                if (field.kind == ValueKind::Signed && (field.value & signBit))
                {
                    // 无实现定义的无符号转有符号转换，也涵盖 INT64_MIN。
                    const auto mask = field.valueBits == 64 ? ~std::uint64_t{0} :
                        (std::uint64_t{1} << field.valueBits) - 1;
                    output << '-' << ((~field.value & mask) + 1);
                }
                else if (field.kind == ValueKind::Boolean) output << (field.value ? "true" : "false");
                else output << field.value;
                output << ')';
            }
            return output.str();
        }

        bool SameIdentity(const threadlayout::Identity& a, const threadlayout::Identity& b)
        {
            return a.machine == 0x8664 && a.machine == b.machine && a.timestamp == b.timestamp &&
                a.imageSize && a.imageSize == b.imageSize && !a.pdbKey.empty() && a.pdbKey == b.pdbKey;
        }
    }

    Projection Project(const threadlayout::Profile& profile, const threadlayout::Identity& sampledIdentity,
        const std::uint32_t objectSize, const std::uint8_t* bytes, const std::size_t availableBytes,
        const std::uint8_t* valid, const std::size_t validSize)
    {
        Projection result;
        result.totalRows = profile.fields.size();
        result.identityMatched = SameIdentity(profile.identity, sampledIdentity) && objectSize &&
            profile.rootSize == objectSize && availableBytes <= objectSize && (!availableBytes || bytes) &&
            (valid ? validSize >= (availableBytes + 7) / 8 : validSize == 0);
        if (!result.totalRows || result.totalRows > 4096) result.identityMatched = false;
        if (!result.identityMatched) return result;
        std::vector<bool> aggregate(result.totalRows, false);
        for (std::size_t i = 0; i < result.totalRows; ++i)
        {
            const auto parent = profile.fields[i].parent;
            if (parent > i) { result.identityMatched = false; return result; }
            if (parent) aggregate[parent - 1] = true;
        }
        result.fields.reserve(result.totalRows);
        // 同一存储的重复别名不用于提高覆盖率；不同位域切片保持独立字段语义。
        std::set<std::tuple<std::uint32_t, std::uint32_t, int, int>> countedStorage;
        for (std::size_t i = 0; i < result.totalRows; ++i)
        {
            const auto& source = profile.fields[i];
            FieldValue field;
            const auto* parent = source.parent ? &result.fields[source.parent - 1] : nullptr;
            field.path = parent ? parent->path + '.' + source.name : source.name;
            field.unionInterpretation = source.unionAlias || (parent && parent->unionInterpretation);
            const auto base = parent ? parent->offset : 0;
            if (base >= objectSize || source.offset >= objectSize - base ||
                (parent && parent->status == FieldStatus::InvalidLayout))
            {
                field.status = FieldStatus::InvalidLayout;
                ++result.unreadRows;
            }
            else
            {
                field.offset = base + source.offset;
                const auto scalar = Describe(source.type);
                field.width = scalar.width;
                field.kind = scalar.kind;
                if (aggregate[i]) { field.status = FieldStatus::Aggregate; ++result.aggregateRows; }
                else if (!scalar.width) { field.status = FieldStatus::UnsupportedType; ++result.unsupportedRows; }
                else if ((source.bitOffset < 0) != (source.bitWidth < 0) || source.bitOffset < -1 ||
                    source.bitWidth < -1 || (source.bitOffset >= 0 && (source.bitWidth <= 0 ||
                        source.bitOffset >= static_cast<int>(scalar.width * 8) ||
                        source.bitWidth > static_cast<int>(scalar.width * 8) - source.bitOffset)))
                {
                    field.status = FieldStatus::InvalidLayout;
                    ++result.unreadRows;
                }
                else if (field.offset >= availableBytes || scalar.width > availableBytes - field.offset)
                {
                    field.status = FieldStatus::OutsideSnapshot;
                    ++result.unreadRows;
                }
                else
                {
                    bool complete = true; // 稀疏回执中任一字节无效时，整个标量都不能显示为零。
                    if (valid)
                    {
                        for (std::uint32_t j = 0; j < scalar.width; ++j)
                        {
                            const auto at = field.offset + j; // 已由上述字段范围检查限制在位图覆盖范围。
                            complete = complete && (valid[at >> 3] & (1U << (at & 7))) != 0;
                        }
                    }
                    if (!complete)
                    {
                        field.status = FieldStatus::OutsideSnapshot;
                        ++result.unreadRows;
                        result.fields.push_back(std::move(field));
                        continue;
                    }
                    // 显式按小端序还原，既不未对齐解引用，也不解引用采样到的指针值。
                    for (std::uint32_t j = 0; j < scalar.width; ++j)
                        field.raw |= std::uint64_t{bytes[field.offset + j]} << (8 * j);
                    field.valueBits = source.bitWidth >= 0 ? static_cast<std::uint32_t>(source.bitWidth) : scalar.width * 8;
                    const auto mask = field.valueBits == 64 ? ~std::uint64_t{0} :
                        (std::uint64_t{1} << field.valueBits) - 1;
                    field.value = (field.raw >> (source.bitOffset >= 0 ? source.bitOffset : 0)) & mask;
                    field.status = FieldStatus::Sampled;
                    field.text = Format(field);
                    ++result.sampledRows;
                    result.unionRows += field.unionInterpretation;
                    if (!field.unionInterpretation && countedStorage.emplace(field.offset, field.width,
                        source.bitOffset, source.bitWidth).second)
                    {
                        ++result.coverageRows;
                    }
                }
            }
            result.fields.push_back(std::move(field));
        }
        return result;
    }

    const char* StatusName(const FieldStatus status)
    {
        switch (status)
        {
        case FieldStatus::Sampled: return "sampled";
        case FieldStatus::Aggregate: return "aggregate";
        case FieldStatus::UnsupportedType: return "unsupported_type";
        case FieldStatus::OutsideSnapshot: return "not_copied";
        case FieldStatus::InvalidLayout: return "invalid_layout";
        }
        return "invalid_layout";
    }
}
