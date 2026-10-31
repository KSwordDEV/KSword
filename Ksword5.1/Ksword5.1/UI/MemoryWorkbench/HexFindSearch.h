#pragma once

// ============================================================
// HexFindSearch.h
// 作用：
// - 查找条（HexFindBar）背后的"纯逻辑层"：把界面输入解析成 MemoryByteSearch 的模式，
//   在一块 QByteArray 上执行一次查找（可被取消），以及只在一小段可见范围内列出全部命中。
// - 只依赖 Qt Core 与 shared/evidence/memory_workbench/MemoryByteSearch，不含任何控件，
//   可以脱离界面在夹具里直接测试；后台线程里运行的就是这里的 RunSearch。
//
// 数据源：ByteArraySource 直接读 QByteArray 的内存，不复制整块数据
//   （StaticByteSource 要按值接收 vector，对大缓冲每次查找都要整块拷贝一次）。
//   引擎按块（默认 256 KiB，可取消的粒度）读取，每块只复制那一块。
//
// 地址模型：缓冲覆盖 [base, base + size)，所有地址都是绝对地址，与画布地址列一致。
// ============================================================

#include "../../../../shared/evidence/memory_workbench/HexViewport.h"
#include "../../../../shared/evidence/memory_workbench/MemoryByteSearch.h"

#include <QByteArray>
#include <QString>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace ks::ui::hexfind
{
    // AddressRange：地址闭区间，与画布高亮层使用同一类型。
    using AddressRange = ksword::memwb::HexViewport::AddressRange;

    // kSearchChunkBytes：后台查找每块读取的字节数。
    // 取 256 KiB：取消标志在每块读取前检查，块越小取消越及时；更小的块会让每块的 memchr 起步成本占比变高。
    inline constexpr std::uint64_t kSearchChunkBytes = 256ULL * 1024ULL;

    // kMaxVisibleHits：可见范围内最多列出多少个命中。
    // 可见范围最多约 64 列 x 数十行（几千字节），全通配模式会让每个字节都命中，上限防止无意义的巨型列表。
    inline constexpr std::size_t kMaxVisibleHits = 8192;

    // Mode：查找模式。
    enum class Mode : int
    {
        Hex = 0,        // 十六进制字节，支持 ?? / A? / ?A 通配，空格逗号分隔或连写
        TextUtf8,       // 文本，按 UTF-8 编码
        TextUtf16Le,    // 文本，按 UTF-16 小端编码
        TextAnsi       // 文本，按当前 Windows ANSI 代码页编码（保留既有模式索引）
    };

    std::uint32_t SystemAnsiCodePage();

    // 显式代码页入口便于验证不同 Windows 区域设置；拒绝替换字符与 best-fit 转换。
    // 仅原始 ASCII 字母参与大小写折叠，多字节字符的全部字节始终精确匹配。
    bool ParseAnsiPattern(
        const QString& text,
        std::uint32_t codePage,
        bool caseSensitive,
        ksword::memwb::SearchPattern& patternOut,
        ksword::memwb::ParseError& errorOut);

    // ParsePattern：把用户输入解析成查找模式。
    // 传入：模式、输入文本、是否区分大小写（只对文本模式有意义）；
    // 传出：patternOut 成功时为模式；errorOut 失败时是错误码与位置；utf8Out（可为空指针）是输入的 UTF-8 字节，
    //       用来把错误位置换算成字符序号；返回 true 表示成功。
    bool ParsePattern(
        Mode mode,
        const QString& text,
        bool caseSensitive,
        ksword::memwb::SearchPattern& patternOut,
        ksword::memwb::ParseError& errorOut,
        QByteArray* utf8Out);

    // DescribeParseError：把解析错误写成给用户看的中文（不含"无效模式："前缀）。
    // 传入：错误、输入的 UTF-8 字节；传出：文字，例如"输入为空"或"第 3 个字符处有误"。
    QString DescribeParseError(const ksword::memwb::ParseError& error, const QByteArray& utf8);

    // ByteArraySource：直接读 QByteArray 的数据源，覆盖 [base, base + size)。
    class ByteArraySource final : public ksword::memwb::IByteSource
    {
    public:
        // 构造：data 数据（隐式共享，不拷贝）；base 起始地址；validMask 非空时必须与 data 等长。
        // 空掩码保留普通文件宿主的“全部有效”约定，内存宿主必须传入真实掩码。
        ByteArraySource(const QByteArray& data, std::uint64_t base, const QByteArray& validMask = QByteArray());

        // Read：见 IByteSource；与数据块部分相交返回 Partial，完全不相交返回 Unreadable，长度 0 返回 Ok。
        ksword::memwb::ReadStatus Read(
            std::uint64_t address,
            std::uint64_t length,
            std::vector<std::uint8_t>& bytesOut,
            std::vector<std::uint8_t>& validOut) override;

    private:
        // m_data：数据本体（隐式共享）。
        QByteArray m_data;
        QByteArray m_validMask; // 可读性快照；值为 0 的字节即使数据填成 00 也不参与模式匹配
        // m_base：数据起始地址。
        std::uint64_t m_base;
    };

    // Outcome：一次 RunSearch 的结果。
    struct Outcome
    {
        bool found = false;         // 是否找到
        std::uint64_t address = 0;  // 命中的起始地址（found 为假时为 0）
        bool wrapped = false;       // 是否进入了回绕段（语义见 MemoryByteSearch.h 第四节）
        bool cancelled = false;     // 是否被取消标志中断
        bool invalid = false;       // 参数非法（空模式、空数据）
    };

    // RunSearch：在缓冲里查找下一个命中（后台线程调用的就是它）。
    // 传入：data/base 缓冲与起始地址；pattern 模式；start 起点（含，语义见 Find）；
    //       direction 方向；wrap 到边界后是否从另一端继续；cancel 取消标志（可为空）。
    // 传出：Outcome。data 为空或模式为空返回 invalid。
    Outcome RunSearch(
        const QByteArray& data,
        std::uint64_t base,
        const ksword::memwb::SearchPattern& pattern,
        std::uint64_t start,
        ksword::memwb::SearchDirection direction,
        bool wrap,
        const std::atomic<bool>* cancel,
        const QByteArray& validMask = QByteArray());

    // HitsInRange：列出 [visibleFirst, visibleLast] 内全部命中（含起点在可见范围之前、但延伸进可见范围的命中）。
    // 传入：data/base 缓冲；pattern 模式；可见范围（闭区间，会夹取到缓冲内）；cap 最多返回几个。
    // 传出：每个命中的闭区间 [起点, 起点 + 模式长度 - 1]，按起点升序，重叠命中都列出。
    // 只扫描"可见范围向前多看 模式长度-1 字节"的一小段，耗时与缓冲大小无关。
    std::vector<AddressRange> HitsInRange(
        const QByteArray& data,
        std::uint64_t base,
        const ksword::memwb::SearchPattern& pattern,
        std::uint64_t visibleFirst,
        std::uint64_t visibleLast,
        std::size_t cap,
        const QByteArray& validMask = QByteArray());
}
