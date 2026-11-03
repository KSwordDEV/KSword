#pragma once

#include <QByteArray>
#include <QString>
#include <QStringList>
#include <QRegularExpression>
#include <QVector>
#include <cstdint>
#include <limits>
#include <algorithm>
#include <bit>

namespace ks::monitor
{
    enum class RawDecodeMode { Parameters, Bytes };
    enum class RawParameterType { Int, Char, Bool, LongLong, Bytes, UChar, Short, UShort, UInt, ULongLong, Float, Double, Pointer, WChar, WinBool, Long, ULong, WinByte, WinWord, WinDword, Handle, SizeT };
    struct RawParameterAllocation { RawParameterType type; int length = 0; };
    struct RawParameterData { int slotBytes = 0; QVector<std::uint64_t> rawWords; };
    struct DecodedParameter { QString value; QByteArray bytes; bool available = false; };
    struct RawDecodeResult { QVector<DecodedParameter> values; QByteArray unallocated; bool valid = false; };

    // Raw values are ABI locations captured by the Agent, never dereferenced
    // memory. The full hexadecimal word is retained even when upper bits of a
    // 32-bit value are unspecified by the calling convention.
    inline RawParameterData ParseRawParameterData(const QString& detail)
    {
        RawParameterData result;
        const bool x64 = detail.contains(QStringLiteral("params=raw abi=x64"));
        const bool x86 = detail.contains(QStringLiteral("params=raw abi=x86"));
        if (!x64 && !x86) return result;
        result.slotBytes = x64 ? 8 : 4;
        if (x64) {
            for (const auto& name : {QStringLiteral("RCX"), QStringLiteral("RDX"), QStringLiteral("R8"), QStringLiteral("R9")}) {
                const auto match = QRegularExpression(QStringLiteral("(?:^| )%1=(0x[0-9a-fA-F]+)(?: |$)").arg(name)).match(detail);
                bool ok = false; const auto value = match.captured(1).toULongLong(&ok, 16);
                if (!match.hasMatch() || !ok) return {};
                result.rawWords.push_back(value);
            }
        }
        const auto match = QRegularExpression(QStringLiteral("stackSlots=\\[([^\\]]*)\\]")).match(detail);
        if (!match.hasMatch()) return {};
        const auto words = match.captured(1).split(QChar(','), Qt::SkipEmptyParts);
        if (words.size() > 4) return {};
        for (const auto& word : words) {
            bool ok = false; const auto value = word.toULongLong(&ok, 16);
            if (!ok || (x86 && value > UINT32_MAX)) return {};
            result.rawWords.push_back(value);
        }
        return result;
    }

    inline int RawParameterElementWidth(const RawParameterAllocation& allocation, int slotBytes = 8)
    {
        switch (allocation.type) {
        case RawParameterType::Int: case RawParameterType::UInt: case RawParameterType::Float: case RawParameterType::WinBool: case RawParameterType::Long: case RawParameterType::ULong: case RawParameterType::WinDword: return 4;
        case RawParameterType::Char: case RawParameterType::UChar: case RawParameterType::Bool: case RawParameterType::WinByte: return 1;
        case RawParameterType::Short: case RawParameterType::UShort: case RawParameterType::WChar: case RawParameterType::WinWord: return 2;
        case RawParameterType::LongLong: case RawParameterType::ULongLong: case RawParameterType::Double: return 8;
        case RawParameterType::Pointer: case RawParameterType::Handle: case RawParameterType::SizeT: return slotBytes;
        case RawParameterType::Bytes: return allocation.length > 0 && allocation.length <= 1024 * 1024 ? allocation.length : 0;
        }
        return 0;
    }
    inline int RawParameterWidth(const RawParameterAllocation& allocation, int slotBytes = 8)
    {
        const int element = RawParameterElementWidth(allocation, slotBytes);
        if (!element || allocation.length < 0 || allocation.length > 1024 * 1024) return 0;
        if (allocation.type == RawParameterType::Bytes) return element;
        const int count = std::max(1, allocation.length);
        return count <= (1024 * 1024) / element ? element * count : 0;
    }
    inline RawDecodeResult DecodeRawParameters(const RawParameterData& data,
        const QVector<RawParameterAllocation>& allocations, RawDecodeMode mode)
    {
        RawDecodeResult result;
        if (data.slotBytes != 4 && data.slotBytes != 8) return result;
        QByteArray bytes;
        for (const auto slot : data.rawWords)
            for (int i = 0; i < data.slotBytes; ++i) bytes.append(static_cast<char>((slot >> (i * 8)) & 0xff));
        qsizetype offset = 0;
        bool exhausted = false;
        for (const auto& allocation : allocations) {
            const int width = RawParameterWidth(allocation, data.slotBytes);
            if (!width) return {};
            const qsizetype consumed = mode == RawDecodeMode::Parameters
                ? ((width + data.slotBytes - 1) / data.slotBytes) * data.slotBytes : width;
            DecodedParameter parameter;
            if (!exhausted && offset <= bytes.size() && consumed <= bytes.size() - offset) {
                parameter.bytes = bytes.mid(offset, width); parameter.available = true;
                const int count = allocation.type == RawParameterType::Bytes ? 1 : std::max(1, allocation.length);
                const int elementWidth = allocation.type == RawParameterType::Bytes ? width : RawParameterElementWidth(allocation, data.slotBytes);
                QStringList elements;
                for (int element = 0; element < count; ++element) {
                    const int elementOffset = element * elementWidth;
                    QString elementValue;
                    std::uint64_t number = 0;
                    for (int i = 0; i < std::min(elementWidth, 8); ++i)
                        number |= std::uint64_t(static_cast<unsigned char>(parameter.bytes[elementOffset + i])) << (i * 8);
                    switch (allocation.type) {
                    case RawParameterType::Int: case RawParameterType::Long: elementValue = QString::number(static_cast<std::int32_t>(number)); break;
                    case RawParameterType::Char: elementValue = QString::number(static_cast<std::int8_t>(number)); break;
                    case RawParameterType::Bool: elementValue = number ? QStringLiteral("true") : QStringLiteral("false"); break;
                    case RawParameterType::LongLong: elementValue = QString::number(static_cast<std::int64_t>(number)); break;
                    case RawParameterType::UChar: case RawParameterType::WinByte: elementValue = QString::number(static_cast<std::uint8_t>(number)); break;
                    case RawParameterType::Short: elementValue = QString::number(static_cast<std::int16_t>(number)); break;
                    case RawParameterType::UShort: case RawParameterType::WChar: case RawParameterType::WinWord: elementValue = QString::number(static_cast<std::uint16_t>(number)); break;
                    case RawParameterType::UInt: case RawParameterType::ULong: case RawParameterType::WinDword: elementValue = QString::number(static_cast<std::uint32_t>(number)); break;
                    case RawParameterType::ULongLong: elementValue = QString::number(static_cast<qulonglong>(number)); break;
                    case RawParameterType::WinBool: elementValue = number ? QStringLiteral("true") : QStringLiteral("false"); break;
                    case RawParameterType::SizeT: elementValue = QString::number(static_cast<qulonglong>(number)); break;
                    case RawParameterType::Pointer: case RawParameterType::Handle: elementValue = QStringLiteral("0x%1").arg(static_cast<qulonglong>(number), data.slotBytes * 2, 16, QLatin1Char('0')); break;
                    case RawParameterType::Float:
                        elementValue = mode == RawDecodeMode::Parameters && data.slotBytes == 8
                            ? QStringLiteral("-") : QString::number(std::bit_cast<float>(static_cast<std::uint32_t>(number)), 'g', 9); break;
                    case RawParameterType::Double:
                        elementValue = mode == RawDecodeMode::Parameters && data.slotBytes == 8
                            ? QStringLiteral("-") : QString::number(std::bit_cast<double>(number), 'g', 17); break;
                    case RawParameterType::Bytes: elementValue = QString::fromLatin1(parameter.bytes.toHex(' ').toUpper()); break;
                    }
                    elements.push_back(elementValue);
                }
                parameter.value = count > 1 ? QChar('[') + elements.join(QStringLiteral(", ")) + QChar(']') : elements.value(0);
                offset += consumed;
            } else exhausted = true;
            result.values.push_back(std::move(parameter));
        }
        result.unallocated = bytes.mid(offset); result.valid = true; return result;
    }
    struct RawParameterLayout { QVector<int> widths; int remainderWidth = 0; };
    inline RawParameterLayout LayoutRawParameters(const RawParameterData& data,
        const QVector<RawParameterAllocation>& allocations, RawDecodeMode mode, int unit)
    {
        RawParameterLayout layout; const int slot = data.slotBytes == 4 ? 4 : 8;
        const qint64 totalBytes = data.slotBytes * data.rawWords.size();
        QVector<int> sizes; qint64 remaining = totalBytes; bool exhausted = false;
        for (const auto& item : allocations) {
            const int width = RawParameterWidth(item, slot);
            const int consumed = mode == RawDecodeMode::Parameters ? ((width + slot - 1) / slot) * slot : width;
            if (!exhausted && consumed <= remaining) { sizes.push_back(consumed * unit); remaining -= consumed; }
            else { exhausted = true; sizes.push_back(1); }
        }
        const qint64 span = totalBytes * unit; qint64 used = 0;
        for (const int width : sizes) { layout.widths.push_back(width); used += width; }
        if (span >= layout.widths.size() && used > span) {
            qint64 excess = used - span;
            for (int i = layout.widths.size() - 1; i >= 0 && excess > 0; --i) {
                const int reduction = static_cast<int>(std::min<qint64>(excess, layout.widths[i] - 1));
                layout.widths[i] -= reduction; used -= reduction; excess -= reduction;
            }
        }
        layout.remainderWidth = static_cast<int>(std::max<qint64>(0, span - used));
        return layout;
    }
    // Allocate a proportional bar while reserving enough room for labels.
    // If the viewport is too narrow, return the minimum readable width and let it scroll.
    inline QVector<int> FitRawAllocationWidths(const QVector<int>& weights, const QVector<int>& minimums, int available)
    {
        QVector<int> result(weights.size(), 0);
        if (weights.size() != minimums.size() || weights.isEmpty()) return result;
        qint64 minTotal = 0; for (int value : minimums) minTotal += std::max(0, value);
        qint64 budget = std::max<qint64>(std::max(0, available), minTotal);
        qint64 totalWeight = 0; for (int value : weights) totalWeight += std::max(1, value);
        QVector<bool> fixed(weights.size(), false);
        bool changed = true;
        while (changed && totalWeight > 0) {
            changed = false;
            for (qsizetype i = 0; i < weights.size(); ++i) {
                const int weight = std::max(1, weights[i]);
                if (!fixed[i] && budget * weight < qint64(std::max(0, minimums[i])) * totalWeight) {
                    fixed[i] = true; result[i] = std::max(0, minimums[i]);
                    budget -= result[i]; totalWeight -= weight; changed = true;
                }
            }
        }
        qint64 usedWeight = 0;
        for (qsizetype i = 0; i < weights.size(); ++i) if (!fixed[i]) {
            const qint64 next = usedWeight + std::max(1, weights[i]);
            result[i] = totalWeight ? int(next * budget / totalWeight - usedWeight * budget / totalWeight) : 0;
            usedWeight = next;
        }
        return result;
    }
    inline QString FormatRawHex(const QByteArray& bytes)
    {
        QString output;
        for (qsizetype base = 0; base < bytes.size(); base += 16) {
            const QByteArray row = bytes.mid(base, 16);
            QString ascii; ascii.reserve(row.size());
            for (const char value : row) {
                const auto ch = static_cast<unsigned char>(value);
                ascii += QChar(ch >= 0x20 && ch <= 0x7e ? ch : '.');
            }
            output += QString::fromLatin1(row.toHex(' ').toUpper()).leftJustified(47, QChar(' '));
            output += QStringLiteral(" | ") + ascii + QChar('\n');
        }
        return output;
    }
}
