#pragma once

// ============================================================
// MemoryByteSearch.h
// 作用：
// - 内存工作台十六进制视图的"查找引擎"。纯 C++20 标准库实现，不依赖 Qt、不依赖
//   Win32，可在离线套件里直接穷举测试；字节用 std::vector<std::uint8_t>，文本用
//   UTF-8 的 std::string。
//
// 取代旧控件（HexEditorWidget）查找功能的缺陷：
//   1. HEX 必须空格分隔，输入 4D5A9000 被判无效     -> 空格/逗号分隔或连写都合法；
//   2. "ASCII 文本"实为 UTF-8 且区分大小写            -> 文本模式可选忽略 ASCII 大小写，
//                                                       并支持 UTF-16LE；
//   3. 没有半字节通配                                  -> A? / ?A / ?? 三种通配；
//   4. 重读时旧结果可套到新数据、编辑后命中高亮不清    -> 本层无状态，结果只含地址，
//                                                       由上层按会话代次丢弃陈旧结果；
//   5. Next 到尾静默回绕                               -> 回绕必须由调用方显式 wrap=true，
//                                                       且 SearchResult::wrapped 如实置位。
// 必须保留的旧行为：允许重叠命中（逐字节步进）、?? 全通配、分块扫描带 patternLength-1
// 的尾部拼接防漏跨块命中、读不到的区间跳过并计数而不是当作 00。
//
// ------------------------------------------------------------
// 一、模式（SearchPattern）
// ------------------------------------------------------------
// bytes/mask 等长。判据：(data[i] & mask[i]) == (bytes[i] & mask[i])。
//   mask 0xFF 精确匹配；0x00 全通配；0xF0 只比高半字节；0x0F 只比低半字节；
//   0xDF 忽略 ASCII 字母大小写（只清掉 bit5，bytes 里存大写字母）。
// description 是便于日志/历史列表展示的规范化文本，不是面向用户的句子：
//   十六进制模式为规范化字节文本，如 "4D 5A ?? A?"；
//   文本模式为 "utf8:" / "utf8/i:" / "utf16le:" / "utf16le/i:" 加原文本（/i 表示忽略大小写）。
// 全通配模式（如 "?? ??"）是合法的，会在每个可读位置命中；调用方若认为无意义自行拒绝。
//
// ------------------------------------------------------------
// 二、解析器
// ------------------------------------------------------------
// ParseHexPattern 文法：记号 = 可选 0x/0X 前缀 + 若干半字节（0-9a-fA-F 或 ?）；
//   记号之间用空白（空格 制表 换行 回车）或逗号分隔，分隔符个数不限；
//   一个记号内部可以连写多个字节（4D5A9000），也可以每个字节各带前缀（0x4D 0x5A）。
//   记号内的半字节两两配对成字节：?? 全通配，A? 只比高半字节，?A 只比低半字节。
//   每个记号的半字节个数必须为偶数，不允许把一个字节拆到两个记号里（"4 D" 非法）。
//   失败时 patternOut 被清空（三个字段全空），errorOut 给出错误码与位置。
// ParseTextPattern：输入是 UTF-8。严格校验（拒绝孤立续字节、截断、过长编码、
//   代理码点 U+D800..U+DFFF、超过 U+10FFFF）。Utf8 输出原字节；Utf16Le 把每个码点
//   转成 UTF-16 小端码元（辅助平面用代理对，每个码元先低字节后高字节）。
//   caseInsensitive 只折叠 ASCII 字母 A-Z/a-z（mask 0xDF）；@ [ ` { 等相邻符号
//   不折叠；UTF-16 时只作用于"高字节为 0 的码元的低字节"，高字节永远精确匹配。
//
// ParseError 只含错误码与位置，不拼接面向用户的句子，界面层自行翻译。
//   Empty      输入为空或只有分隔符；position 恒为 0。
//   BadPattern 其它一切非法输入；position 是**原始输入里的字节偏移**：
//     * 非法字符（含 0x 出现在记号中间、非 ASCII 字符）：该字符的偏移；
//     * 半字节个数为奇数：最后那个落单半字节的偏移（"4D5" 为 2）；
//     * 0x 前缀后面没有任何半字节（"0x"、"0x 4D"）：该前缀 '0' 的偏移；
//     * 非法 UTF-8：出错码点的首字节偏移。
//   同一输入里有多处错误时报告扫描顺序里最先发现的那一处。
//
// ------------------------------------------------------------
// 三、数据源（IByteSource）
// ------------------------------------------------------------
// Read(address, length, bytesOut, validOut) 读 [address, address+length) 的字节：
//   Ok         全部读到；引擎不再检查 validOut。
//   Partial    部分读到；validOut 与 bytesOut 等长，1 表示该字节真实读到，
//              未读到的字节内容无意义（可以是 0），引擎绝不会在其上匹配。
//   Unreadable 一个字节都没读到；引擎不检查两个输出。
// 引擎保证不会请求超出 SearchRange 的地址，且 address+length-1 不溢出。
// 数据源违约（返回的 bytesOut 比 length 短，或 Partial 的 validOut 比 length 短）
// 按 Unreadable 处理——宁可漏报，也不在没读到的字节上匹配。
// StaticByteSource(base, data) 是内置的单块内存数据源：覆盖 [base, base+data.size())，
// 与请求区间部分相交返回 Partial，完全不相交返回 Unreadable。
//
// ------------------------------------------------------------
// 四、查找语义（Find）
// ------------------------------------------------------------
// 范围 SearchRange 是闭区间 [first, last]。匹配必须整体落在范围内，所以匹配起点
// 的最大值是 last-(L-1)（L 为模式长度）；范围放不下一个模式则无结果。
//   Forward   从 startAddress 起（含）向后找，匹配起点 >= startAddress。
//   Backward  从 startAddress 起（含）向前找，匹配起点 <= startAddress。
//   重叠命中：逐字节步进，AA AA AA 里找 AA AA 的起点有两个（偏移 0 和 1）。
//   不跨越不可读字节：匹配窗口里每个字节都必须真实读到。
//   startAddress 允许落在范围外：Forward 下小于 first 按 first 处理（不算回绕），
//     大于最大起点则第一段为空；Backward 下大于最大起点按最大起点处理，小于 first
//     则第一段为空。
//   wrap=false：扫到边界即停，found=false 且 wrapped=false。绝不静默回绕。
//   wrap=true ：第一段没找到就从另一端继续，直到回到起点（第二段只含"起点之前"的
//     候选，不会重复扫描第一段）。进入第二段时 wrapped 置 true；因此
//       found && !wrapped   命中在第一段；
//       found &&  wrapped   命中在回绕之后；
//       !found && wrapped   整个范围都扫过、没有命中。
//     第二段为空（如 Forward 且 startAddress<=first）时 wrapped 保持 false。
//   起点步进：Next/Prev 时调用方要把上次命中地址 ±1，address 在 0 或 UINT64_MAX
//     处会发生 64 位回绕，那会让 Find 把"从头开始"误当成"紧接着往后"，所以提供
//     AdvanceSearchStart 做不溢出的 ±1，返回 false 表示没有下一个起点。
//
// 分块：每块读 chunkBytes 字节，块与块之间保留 L-1 字节重叠，所以跨块命中不会漏；
//   chunkBytes 被夹到 [L, kMaxSearchChunkBytes]（EffectiveChunkBytes）：小于模式长度时
//   夹到 L，每块至少推进 1 个候选起点，既不死循环也不漏。模式比块的一半还长时读取
//   放大约 L/(块内起点数) 倍，实际使用中模式只有几十字节所以不是问题。
//   取消标志在每个分块读取之前检查（含第一块）：置位则立即返回 cancelled=true，
//   此时 found 恒为 false，已扫描的统计保留。
//
// 统计口径（scannedBytes / skippedUnreadableBytes）：以"候选起点位置"计，每个位置
//   至多计一次（块间重叠不重复计）。位置自身字节真实读到计入 scanned，读不到计入
//   skipped，二者之和 = 已检查的候选起点数。范围末尾 L-1 个字节不可能是起点，不计入。
//   所以整段扫完时 scanned + skipped == (last-first+1) - (L-1)。命中时只统计到命中位置
//   （Forward 含命中起点，Backward 含命中起点）。
//
// 参数非法（模式为空、bytes/mask 长度不等、first > last）：返回 invalidArguments=true，
//   其它字段为初值。这属于编程错误，解析器产出的模式不会触发。
//
// CountMatches：在整个范围内向前扫，重叠命中都计。cap 是上限：计数达到 cap 就停并
//   置 capped=true（capped 表示"至少 cap 个"，实际可能恰好 cap 个也可能更多）；
//   cap 为 0 时一个字节都不扫、直接 capped=true。取消时 cancelled=true，count 是已计数。
//
// 性能：纯字面量（全 0xFF 掩码）模式走快速路径——取第一个精确字节做 memchr 定位候选，
//   再 memcmp 全模式；带通配的模式在第一个精确字节上同样先 memchr，没有任何精确字节时
//   逐位置比较。16 MiB 随机缓冲上 4 字节字面量单次完整扫描的实测数字见测试输出。
//
// 测试：KswordARKLightTests/MemoryByteSearchTests.cpp（套件入口 RunMemwbByteSearchTests，
// 套件名 "MEMWB byte search"）。
// ============================================================

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace ksword::memwb
{
    // kDefaultSearchChunkBytes：默认每块读取字节数（1 MiB）。
    inline constexpr std::uint64_t kDefaultSearchChunkBytes = 1ULL << 20;

    // kMaxSearchChunkBytes：每块读取字节数的上限（64 MiB），防止调用方传入荒谬值后
    // 一次分配过大的缓冲。
    inline constexpr std::uint64_t kMaxSearchChunkBytes = 64ULL << 20;

    // SearchPattern：一个已解析的查找模式。
    struct SearchPattern
    {
        // bytes：模式字节。通配位对应的值无意义（解析器置 0），比较时先与 mask 相与。
        std::vector<std::uint8_t> bytes;
        // mask：与 bytes 等长；0xFF 精确，0x00 全通配，0xF0/0x0F 半字节通配，
        // 0xDF 忽略 ASCII 字母大小写。
        std::vector<std::uint8_t> mask;
        // description：规范化的展示文本，见文件头说明；不是面向用户的句子。
        std::string description;
    };

    // ParseErrorCode：解析失败的原因。None 仅在成功时出现。
    enum class ParseErrorCode
    {
        None = 0,
        Empty,       // 输入为空或只有分隔符
        BadPattern,  // 其它非法输入（字符、奇数半字节、孤立前缀、非法 UTF-8）
        UnrepresentableText, // 文本无法按所选代码页无损编码
    };

    // ParseError：解析失败的详情，只含错误码与位置，不含面向用户的句子。
    struct ParseError
    {
        // code：失败原因；成功时为 None。
        ParseErrorCode code = ParseErrorCode::None;
        // position：出错处在原始输入里的字节偏移；Empty 与成功时为 0。
        std::size_t position = 0;
    };

    // TextEncoding：文本模式的目标编码。
    enum class TextEncoding
    {
        Utf8 = 0,
        Utf16Le,
    };

    // ParseHexPattern：把十六进制文本解析成模式。
    // 传入：text 输入文本（语法见文件头）；
    // 传出：patternOut 成功时为模式，失败时三个字段全空；
    //       errorOut 成功时 code=None、position=0，失败时见 ParseError；
    //       返回 true 表示成功。
    bool ParseHexPattern(std::string_view text, SearchPattern& patternOut, ParseError& errorOut);

    // ParseTextPattern：把 UTF-8 文本解析成指定编码的模式。
    // 传入：text UTF-8 文本；encoding 目标编码；
    //       caseInsensitive 为 true 时 ASCII 字母用 0xDF 掩码（UTF-16 只作用于低字节）。
    // 传出：patternOut/errorOut/返回值 同 ParseHexPattern。
    bool ParseTextPattern(
        std::string_view text,
        TextEncoding encoding,
        bool caseInsensitive,
        SearchPattern& patternOut,
        ParseError& errorOut);

    // ReadStatus：一次读取的结果，语义见文件头第三节。
    enum class ReadStatus
    {
        Ok = 0,
        Partial,
        Unreadable,
    };

    // IByteSource：查找引擎读取目标字节的抽象，由调用方（会话/驱动/测试）实现。
    class IByteSource
    {
    public:
        // 虚析构：允许经基类指针销毁实现。
        virtual ~IByteSource() = default;

        // Read：读 [address, address+length) 的字节。
        // 传入：address 起始地址；length 字节数（引擎保证区间不溢出 64 位）。
        // 传出：bytesOut 读到的字节（长度应为 length）；
        //       validOut 与 bytesOut 等长，1 表示该字节真实读到（仅 Partial 时被读取）；
        //       返回值见 ReadStatus。实现可以复用两个向量的容量。
        virtual ReadStatus Read(
            std::uint64_t address,
            std::uint64_t length,
            std::vector<std::uint8_t>& bytesOut,
            std::vector<std::uint8_t>& validOut) = 0;
    };

    // StaticByteSource：内置的单块内存数据源，覆盖 [base, base+data.size())。
    // 实现很短，直接内联在头文件里，便于测试与上层随手构造。
    class StaticByteSource final : public IByteSource
    {
    public:
        // 构造：base 数据对应的起始地址；data 数据本体（按值接收，可 std::move 传入）。
        // 若 base+data.size() 会超过 2^64，尾部多出的部分被截掉。
        StaticByteSource(std::uint64_t base, std::vector<std::uint8_t> data)
            : base_(base)
            , data_(std::move(data))
        {
            // base 起最多放 (2^64 - base) 个字节；maxIndex 是最大合法下标，多出的截掉。
            const std::uint64_t maxIndex = 0xFFFFFFFFFFFFFFFFULL - base_;
            if (!data_.empty() && static_cast<std::uint64_t>(data_.size() - 1) > maxIndex)
            {
                data_.resize(static_cast<std::size_t>(maxIndex + 1));
            }
        }

        // Read：见 IByteSource。与数据块部分相交返回 Partial，完全不相交返回 Unreadable，
        // 请求长度为 0 返回 Ok。未覆盖处 bytesOut 填 0、validOut 填 0。
        ReadStatus Read(
            std::uint64_t address,
            std::uint64_t length,
            std::vector<std::uint8_t>& bytesOut,
            std::vector<std::uint8_t>& validOut) override
        {
            // 先整体清零：未覆盖的部分就是 0 且无效。
            bytesOut.assign(static_cast<std::size_t>(length), 0);
            validOut.assign(static_cast<std::size_t>(length), 0);
            if (length == 0)
            {
                return ReadStatus::Ok;
            }
            if (data_.empty())
            {
                return ReadStatus::Unreadable;
            }

            // 求请求区间与数据块的交集；请求末端可能越过 2^64，饱和处理。
            const std::uint64_t maxAddress = 0xFFFFFFFFFFFFFFFFULL;
            const std::uint64_t dataLast = base_ + (data_.size() - 1);
            const std::uint64_t requestLast = (length - 1 > maxAddress - address) ? maxAddress : (address + (length - 1));
            const std::uint64_t overlapLo = (std::max)(address, base_);
            const std::uint64_t overlapHi = (std::min)(requestLast, dataLast);
            if (overlapLo > overlapHi)
            {
                return ReadStatus::Unreadable;
            }

            // 把交集拷到输出的对应位置并标有效。
            const std::size_t count = static_cast<std::size_t>(overlapHi - overlapLo) + 1;
            const std::size_t outOffset = static_cast<std::size_t>(overlapLo - address);
            const std::size_t dataOffset = static_cast<std::size_t>(overlapLo - base_);
            std::memcpy(bytesOut.data() + outOffset, data_.data() + dataOffset, count);
            std::memset(validOut.data() + outOffset, 1, count);
            return (count == length) ? ReadStatus::Ok : ReadStatus::Partial;
        }

    private:
        // base_：数据块起始地址。
        std::uint64_t base_ = 0;
        // data_：数据块本体。
        std::vector<std::uint8_t> data_;
    };

    // SearchRange：查找范围，闭区间 [first, last]。
    struct SearchRange
    {
        // first：范围起始地址（含）。
        std::uint64_t first = 0;
        // last：范围结束地址（含）。
        std::uint64_t last = 0;
    };

    // SearchDirection：查找方向。
    enum class SearchDirection
    {
        Forward = 0,
        Backward,
    };

    // SearchResult：一次 Find 的结果。
    struct SearchResult
    {
        // found：是否找到。取消时恒为 false。
        bool found = false;
        // address：命中的起始地址；found 为 false 时为 0。
        std::uint64_t address = 0;
        // wrapped：是否进入了回绕段，语义见文件头第四节。
        bool wrapped = false;
        // cancelled：是否被取消标志中断。
        bool cancelled = false;
        // invalidArguments：参数非法（模式为空/掩码不等长/范围颠倒）。
        bool invalidArguments = false;
        // scannedBytes：已检查且自身字节真实读到的候选起点数。
        std::uint64_t scannedBytes = 0;
        // skippedUnreadableBytes：已检查但自身字节读不到的候选起点数。
        std::uint64_t skippedUnreadableBytes = 0;
    };

    // CountResult：一次 CountMatches 的结果。
    struct CountResult
    {
        // count：已计数的命中数（重叠命中都计）。
        std::uint64_t count = 0;
        // capped：是否因达到 cap 而停止（"至少 cap 个"）。
        bool capped = false;
        // cancelled：是否被取消标志中断。
        bool cancelled = false;
        // invalidArguments：参数非法，同 SearchResult。
        bool invalidArguments = false;
        // scannedBytes：同 SearchResult::scannedBytes。
        std::uint64_t scannedBytes = 0;
        // skippedUnreadableBytes：同 SearchResult::skippedUnreadableBytes。
        std::uint64_t skippedUnreadableBytes = 0;
    };

    // Find：在范围内查找下一个命中，语义见文件头第四节。
    // 传入：source 数据源；pattern 模式；range 查找范围；startAddress 起点（含）；
    //       direction 方向；wrap 到边界后是否从另一端继续；
    //       cancelFlag 取消标志（可为空，每个分块之前检查）；
    //       chunkBytes 每块读取字节数（见 EffectiveChunkBytes 的夹取规则）。
    // 传出：SearchResult。
    SearchResult Find(
        IByteSource& source,
        const SearchPattern& pattern,
        const SearchRange& range,
        std::uint64_t startAddress,
        SearchDirection direction,
        bool wrap,
        const std::atomic<bool>* cancelFlag = nullptr,
        std::uint64_t chunkBytes = kDefaultSearchChunkBytes);

    // CountMatches：统计范围内的命中数（向前扫，重叠命中都计，达到 cap 就停）。
    // 传入：参数含义同 Find；cap 为计数上限。
    // 传出：CountResult。
    CountResult CountMatches(
        IByteSource& source,
        const SearchPattern& pattern,
        const SearchRange& range,
        std::uint64_t cap,
        const std::atomic<bool>* cancelFlag = nullptr,
        std::uint64_t chunkBytes = kDefaultSearchChunkBytes);

    // EffectiveChunkBytes：把调用方给的 chunkBytes 夹成实际使用的块大小。
    // 传入：chunkBytes 调用方设定值；patternLength 模式字节数。
    // 传出：clamp(chunkBytes, patternLength, kMaxSearchChunkBytes)，模式长度优先于上限。
    inline std::uint64_t EffectiveChunkBytes(std::uint64_t chunkBytes, std::uint64_t patternLength)
    {
        // 先压到上限，再抬到模式长度：模式长度优先，保证每块至少有一个候选起点。
        const std::uint64_t capped = (std::min)(chunkBytes, kMaxSearchChunkBytes);
        return (std::max)(capped, patternLength);
    }

    // AdvanceSearchStart：不溢出地把"上次命中地址"推进一步，作为下一次 Find 的起点。
    // 传入：address 上次命中地址；direction 方向。
    // 传出：nextOut 成功时为 Forward 的 address+1 或 Backward 的 address-1；
    //       返回 false 表示已到地址空间尽头（Forward 且 address 为 UINT64_MAX，
    //       或 Backward 且 address 为 0），nextOut 不被修改。
    inline bool AdvanceSearchStart(std::uint64_t address, SearchDirection direction, std::uint64_t& nextOut)
    {
        if (direction == SearchDirection::Forward)
        {
            if (address == 0xFFFFFFFFFFFFFFFFULL)
            {
                return false;
            }
            nextOut = address + 1;
            return true;
        }
        if (address == 0)
        {
            return false;
        }
        nextOut = address - 1;
        return true;
    }
}
