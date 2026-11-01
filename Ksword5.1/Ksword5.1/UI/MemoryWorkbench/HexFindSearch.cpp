// HexFindSearch.cpp
// 作用：HexFindSearch.h 的实现——模式解析、QByteArray 数据源、一次查找、可见范围命中列表。

#include "HexFindSearch.h"

#include "HexViewFormat.h"

#include <algorithm>
#include <cstring>
#include <limits>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace ks::ui::hexfind
{
    std::uint32_t SystemAnsiCodePage()
    {
#ifdef _WIN32
        return GetACP();
#else
        return 65001;
#endif
    }

    bool ParseAnsiPattern(
        const QString& text,
        std::uint32_t codePage,
        bool caseSensitive,
        ksword::memwb::SearchPattern& patternOut,
        ksword::memwb::ParseError& errorOut)
    {
        using ksword::memwb::ParseErrorCode;
        patternOut = {};
        errorOut = {};
        if (text.isEmpty())
        {
            errorOut.code = ParseErrorCode::Empty;
            return false;
        }
#ifdef _WIN32
        ksword::memwb::SearchPattern parsed;
        std::size_t utf8Offset = 0;
        for (qsizetype index = 0; index < text.size();)
        {
            const QChar first = text.at(index);
            const bool pair = first.isHighSurrogate() && index + 1 < text.size()
                && text.at(index + 1).isLowSurrogate();
            if (first.isSurrogate() && !pair)
            {
                errorOut = {ParseErrorCode::BadPattern, utf8Offset};
                return false;
            }
            const int units = pair ? 2 : 1;
            const wchar_t input[2] = {static_cast<wchar_t>(first.unicode()),
                pair ? static_cast<wchar_t>(text.at(index + 1).unicode()) : wchar_t{0}};
            char encoded[8]{};
            BOOL usedDefault = FALSE;
            const bool unicodePage = codePage == CP_UTF8 || codePage == 54936;
            const int count = WideCharToMultiByte(codePage,
                unicodePage ? WC_ERR_INVALID_CHARS : WC_NO_BEST_FIT_CHARS,
                input, units, encoded, static_cast<int>(sizeof(encoded)), nullptr,
                unicodePage ? nullptr : &usedDefault);
            wchar_t roundTrip[2]{};
            const int decoded = count > 0 && !usedDefault
                ? MultiByteToWideChar(codePage, MB_ERR_INVALID_CHARS, encoded, count, roundTrip, 2) : 0;
            if (decoded != units || roundTrip[0] != input[0] || (pair && roundTrip[1] != input[1]))
            {
                errorOut = {ParseErrorCode::UnrepresentableText, utf8Offset};
                return false;
            }
            // GBK/Big5 的尾字节可能落在 A-Z/a-z，不能逐字节套用 UTF-8 的折叠规则。
            const ushort scalar = first.unicode();
            const bool fold = !caseSensitive && count == 1
                && ((scalar >= 'A' && scalar <= 'Z') || (scalar >= 'a' && scalar <= 'z'))
                && static_cast<unsigned char>(encoded[0]) == scalar;
            for (int byte = 0; byte < count; ++byte)
            {
                const auto value = static_cast<std::uint8_t>(encoded[byte]);
                parsed.bytes.push_back(fold ? static_cast<std::uint8_t>(value & 0xDF) : value);
                parsed.mask.push_back(fold ? 0xDF : 0xFF);
            }
            utf8Offset += pair ? 4 : scalar < 0x80 ? 1 : scalar < 0x800 ? 2 : 3;
            index += units;
        }
        parsed.description = "ansi-cp" + std::to_string(codePage) + (caseSensitive ? ":" : "/i:");
        const QByteArray utf8 = text.toUtf8();
        parsed.description.append(utf8.constData(), static_cast<std::size_t>(utf8.size()));
        patternOut = std::move(parsed);
        return true;
#else
        // 非 Windows 夹具仅提供 UTF-8；不冒充其它平台拥有 Windows 代码页转换。
        if (codePage == 65001)
        {
            const QByteArray utf8 = text.toUtf8();
            return ksword::memwb::ParseTextPattern(
                std::string_view(utf8.constData(), static_cast<std::size_t>(utf8.size())),
                ksword::memwb::TextEncoding::Utf8, !caseSensitive, patternOut, errorOut);
        }
        errorOut.code = ParseErrorCode::UnrepresentableText;
        return false;
#endif
    }

    // 解析用户输入。
    bool ParsePattern(
        Mode mode,
        const QString& text,
        bool caseSensitive,
        ksword::memwb::SearchPattern& patternOut,
        ksword::memwb::ParseError& errorOut,
        QByteArray* utf8Out)
    {
        // utf8：输入的 UTF-8 字节；解析器按字节偏移报告错误位置。
        const QByteArray utf8 = text.toUtf8();
        if (utf8Out != nullptr)
        {
            *utf8Out = utf8;
        }
        const std::string_view view(utf8.constData(), static_cast<std::size_t>(utf8.size()));

        if (mode == Mode::Hex)
        {
            return ksword::memwb::ParseHexPattern(view, patternOut, errorOut);
        }
        if (mode == Mode::TextAnsi)
        {
            return ParseAnsiPattern(text, SystemAnsiCodePage(), caseSensitive, patternOut, errorOut);
        }
        const ksword::memwb::TextEncoding encoding = (mode == Mode::TextUtf16Le)
            ? ksword::memwb::TextEncoding::Utf16Le
            : ksword::memwb::TextEncoding::Utf8;
        return ksword::memwb::ParseTextPattern(view, encoding, !caseSensitive, patternOut, errorOut);
    }

    // 错误描述：只给"哪里错了"，前缀由调用方加。
    QString DescribeParseError(const ksword::memwb::ParseError& error, const QByteArray& utf8)
    {
        if (error.code == ksword::memwb::ParseErrorCode::Empty)
        {
            return QStringLiteral("输入为空");
        }

        // 位置换算成 1 起的字符序号；输入里有中文时字节偏移与字符序号不同。
        const std::size_t charIndex = hexview_format::CharIndexFromUtf8Offset(utf8, error.position);
        if (error.code == ksword::memwb::ParseErrorCode::UnrepresentableText)
        {
            return QStringLiteral("第 %1 个字符无法用所选 ANSI 代码页无损表示").arg(static_cast<qulonglong>(charIndex) + 1ULL);
        }
        return QStringLiteral("第 %1 个字符处有误").arg(static_cast<qulonglong>(charIndex) + 1ULL);
    }

    // 构造：保存数据与基址。
    ByteArraySource::ByteArraySource(const QByteArray& data, std::uint64_t base, const QByteArray& validMask)
        : m_data(data)
        , m_validMask(validMask)
        , m_base(base)
    {
    }

    // 读取：与 StaticByteSource 同一套交集规则，但直接从 QByteArray 拷出，不持有第二份整块数据。
    ksword::memwb::ReadStatus ByteArraySource::Read(
        std::uint64_t address,
        std::uint64_t length,
        std::vector<std::uint8_t>& bytesOut,
        std::vector<std::uint8_t>& validOut)
    {
        // 先整体清零：未覆盖的部分内容为 0 且无效。
        bytesOut.assign(static_cast<std::size_t>(length), 0);
        validOut.assign(static_cast<std::size_t>(length), 0);
        if (length == 0)
        {
            return ksword::memwb::ReadStatus::Ok;
        }
        if (m_data.isEmpty() || (!m_validMask.isEmpty() && m_validMask.size() != m_data.size())
            || static_cast<std::uint64_t>(m_data.size() - 1) > std::numeric_limits<std::uint64_t>::max() - m_base)
        {
            return ksword::memwb::ReadStatus::Unreadable;
        }

        // 求请求区间与数据块的交集；请求末端可能越过 2^64，饱和处理。
        const std::uint64_t maxAddress = 0xFFFFFFFFFFFFFFFFULL;
        const std::uint64_t dataLast = m_base + (static_cast<std::uint64_t>(m_data.size()) - 1ULL);
        const std::uint64_t requestLast = (length - 1ULL > maxAddress - address)
            ? maxAddress
            : (address + (length - 1ULL));
        const std::uint64_t overlapLow = (std::max)(address, m_base);
        const std::uint64_t overlapHigh = (std::min)(requestLast, dataLast);
        if (overlapLow > overlapHigh)
        {
            return ksword::memwb::ReadStatus::Unreadable;
        }

        // 把交集拷到输出的对应位置并标有效。
        const std::size_t count = static_cast<std::size_t>(overlapHigh - overlapLow) + 1U;
        const std::size_t outOffset = static_cast<std::size_t>(overlapLow - address);
        const std::size_t dataOffset = static_cast<std::size_t>(overlapLow - m_base);
        std::memcpy(bytesOut.data() + outOffset, m_data.constData() + dataOffset, count);
        if (m_validMask.isEmpty())
        {
            // 完整文件缓冲保留批量填充，避免把大文件查找退化成逐字节循环。
            std::memset(validOut.data() + outOffset, 1, count);
            return (count == length) ? ksword::memwb::ReadStatus::Ok : ksword::memwb::ReadStatus::Partial;
        }
        // 保留读掩码的孔洞：模式通配符也不能把未读填充值当作真实字节命中。
        // readableCount：请求中实际可读的字节数，决定 Ok/Partial/Unreadable 状态。
        std::size_t readableCount = 0;
        for (std::size_t i = 0; i < count; ++i)
        {
            const bool readable = m_validMask.at(static_cast<qsizetype>(dataOffset + i)) == 1;
            validOut[outOffset + i] = readable ? 1 : 0;
            readableCount += readable ? 1U : 0U;
        }
        if (readableCount == 0)
        {
            return ksword::memwb::ReadStatus::Unreadable;
        }
        return (readableCount == length) ? ksword::memwb::ReadStatus::Ok : ksword::memwb::ReadStatus::Partial;
    }

    // 一次查找。
    Outcome RunSearch(
        const QByteArray& data,
        std::uint64_t base,
        const ksword::memwb::SearchPattern& pattern,
        std::uint64_t start,
        ksword::memwb::SearchDirection direction,
        bool wrap,
        const std::atomic<bool>* cancel,
        const QByteArray& validMask)
    {
        Outcome outcome;
        if (data.isEmpty() || pattern.bytes.empty() || pattern.bytes.size() != pattern.mask.size()
            || (!validMask.isEmpty() && validMask.size() != data.size())
            || static_cast<std::uint64_t>(data.size() - 1) > std::numeric_limits<std::uint64_t>::max() - base)
        {
            outcome.invalid = true;
            return outcome;
        }

        // range：缓冲覆盖的闭区间；缓冲贴着 2^64 末端时 base+size-1 恰好是最大地址，不会溢出。
        ksword::memwb::SearchRange range;
        range.first = base;
        range.last = base + (static_cast<std::uint64_t>(data.size()) - 1ULL);

        ByteArraySource source(data, base, validMask);
        const ksword::memwb::SearchResult result = ksword::memwb::Find(
            source, pattern, range, start, direction, wrap, cancel, kSearchChunkBytes);
        outcome.found = result.found;
        outcome.address = result.address;
        outcome.wrapped = result.wrapped;
        outcome.cancelled = result.cancelled;
        outcome.invalid = result.invalidArguments;
        return outcome;
    }

    // 可见范围内的全部命中。
    std::vector<AddressRange> HitsInRange(
        const QByteArray& data,
        std::uint64_t base,
        const ksword::memwb::SearchPattern& pattern,
        std::uint64_t visibleFirst,
        std::uint64_t visibleLast,
        std::size_t cap,
        const QByteArray& validMask)
    {
        std::vector<AddressRange> hits;
        if (data.isEmpty() || pattern.bytes.empty() || pattern.bytes.size() != pattern.mask.size()
            || visibleFirst > visibleLast || cap == 0
            || (!validMask.isEmpty() && validMask.size() != data.size())
            || static_cast<std::uint64_t>(data.size() - 1) > std::numeric_limits<std::uint64_t>::max() - base)
        {
            return hits;
        }

        // 缓冲范围与模式长度；dataLast 是缓冲最后一个字节的地址。
        const std::uint64_t dataFirst = base;
        const std::uint64_t dataLast = base + (static_cast<std::uint64_t>(data.size()) - 1ULL);
        const std::uint64_t length = static_cast<std::uint64_t>(pattern.bytes.size());

        // 扫描范围：可见范围两侧各多看 length-1 字节再夹取到缓冲内——
        // 向前多看：起点在可见范围之前、尾部延伸进来的命中也要算；
        // 向后多看：引擎要求匹配整体落在范围内，起点在可见末字节、尾部越出可见范围的命中不多看就会漏。
        const std::uint64_t lookAround = length - 1ULL;
        std::uint64_t scanFirst = dataFirst;
        if (visibleFirst > dataFirst)
        {
            // room：可见起点距缓冲起点的字节数；够一个 lookAround 才能往前退，否则退到缓冲起点。
            const std::uint64_t room = visibleFirst - dataFirst;
            scanFirst = (room >= lookAround) ? visibleFirst - lookAround : dataFirst;
        }
        const std::uint64_t reach = (visibleLast > 0xFFFFFFFFFFFFFFFFULL - lookAround)
            ? 0xFFFFFFFFFFFFFFFFULL
            : visibleLast + lookAround;
        const std::uint64_t scanLast = (std::min)(reach, dataLast);
        if (scanFirst > scanLast || visibleFirst > dataLast)
        {
            return hits;
        }

        // Compile only significant mask positions once. Stream one immutable
        // range, retaining readable-run length so wildcard bytes never match holes.
        std::vector<std::pair<std::size_t, std::uint8_t>> significant;
        significant.reserve(pattern.bytes.size());
        for (std::size_t index = 0; index < pattern.bytes.size(); ++index)
            if (pattern.mask[index] != 0) significant.push_back({index,
                static_cast<std::uint8_t>(pattern.bytes[index] & pattern.mask[index])});
        const auto firstOffset = static_cast<std::size_t>(scanFirst - base);
        const auto lastOffset = static_cast<std::size_t>(scanLast - base);
        std::size_t readableRun = 0;
        for (std::size_t end = firstOffset; end <= lastOffset && hits.size() < cap; ++end)
        {
            if (!validMask.isEmpty() && validMask.at(static_cast<qsizetype>(end)) != 1)
            { readableRun = 0; continue; }
            ++readableRun;
            if (readableRun < length) continue;
            const auto candidate = end - static_cast<std::size_t>(length - 1);
            const auto address = base + candidate;
            if (address > visibleLast) break;
            if (base + end < visibleFirst) continue;
            bool matches = true;
            for (const auto& term : significant)
            {
                const auto byte = static_cast<std::uint8_t>(data.at(static_cast<qsizetype>(candidate + term.first)));
                if ((byte & pattern.mask[term.first]) != term.second) { matches = false; break; }
            }
            if (matches) hits.push_back(AddressRange{address, base + end});
        }
        return hits;
    }
}
