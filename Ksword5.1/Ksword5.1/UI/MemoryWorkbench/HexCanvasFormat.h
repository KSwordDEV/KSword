#pragma once

// ============================================================
// HexCanvasFormat.h
// 作用：
// - HexCanvas 的"字节 <-> 文本"纯函数集合：复制出去的五种格式、粘贴进来的十六进制解析。
// - 另有"自适应行宽"的两个纯函数 RowWidthChars / ChooseAutoBytesPerRow（一行内容占多少字符、
//   视口放得下哪一档行宽），HexCanvas 的自适应模式与离屏测试共用同一份公式。
// - 全部是无状态纯函数，不依赖任何控件，可以脱离界面单独测试。
// - 之所以单独成文件：HexCanvas 本体已经承担滚动、绘制、输入三块职责，
//   文本格式化再放进去会让任何一个文件超过 800 行。
//
// 约定：
// - 十六进制一律大写（41 而不是 0x41 的小写写法 0x4a）。
// - "可见 ASCII"指 0x20..0x7E，其余字节在文本里一律显示为点号。
// ============================================================

#include <QByteArray>
#include <QFont>
#include <QString>

#include <array>
#include <cstdint>

namespace ks::ui::hexcanvas_format
{
    // All memory canvases share the same Latin monospace and CJK fallback.
    QFont BuildFixedFont();
    // kAutoBytesPerRowCandidates：自适应行宽的候选集合，按"从大到小"排列。
    // 只能取 HexViewport 支持的 8/16/32/48/64；48 是 16 的倍数，行起点仍 16 对齐，因此可以参与自适应。
    // 想把某一档排除出自适应，从这里删掉一项即可（调用方遍历的就是这个数组）。
    inline constexpr std::array<int, 5> kAutoBytesPerRowCandidates = { 64, 48, 32, 16, 8 };

    // RowWidthChars：一行内容占用的字符数（地址列 + 十六进制区 + ASCII 区 + 各处间隙与左右边距）。
    // 用法：内容像素宽度 = RowWidthChars(...) * 单个等宽字符宽度，与 HexCanvas::recomputeLayout 算出的
    //       contentWidth 恒等（由离屏测试固定，防止两份公式漂移）。
    // 传入：bytesPerRow 每行字节数；groupSize 十六进制分组字节数（1/2/4/8）；
    //       addressDigits 地址列位数（8 或 16）。
    // 传出：字符数；bytesPerRow 小于 1 时返回 0。
    // 公式：1(左边距) + 地址位数 + 2(间隔) + 十六进制区 + 2(间隔) + ASCII 区 + 1(右边距)；
    //       十六进制区 = (n-1)*3 + 额外间隔 + 2，额外间隔：第 c 列 c%8==0 加 2（中缝），
    //       否则 groupSize>1 且 c%groupSize==0 加 1（组间隙）。
    int RowWidthChars(int bytesPerRow, int groupSize, int addressDigits);

    // ChooseAutoBytesPerRow：在视口宽度内选"放得下的最大行宽"；一个都放不下就退到最小的 8（由横向滚动条兜底）。
    // 用法：HexCanvas 的自适应模式在视口尺寸、分组、字体、地址位数变化后调用它。
    // 传入：viewportWidthPx 视口像素宽度（不含竖向滚动条）；charWidthPx 单个等宽字符的像素宽度
    //       （小于 1 按 1 处理）；groupSize 分组字节数；addressDigits 地址列位数。
    // 传出：kAutoBytesPerRowCandidates 里的一个值；结果只取决于入参（纯函数，没有滞回，因此不会来回抖动）。
    int ChooseAutoBytesPerRow(int viewportWidthPx, int charWidthPx, int groupSize, int addressDigits);

    // kLoadingGlyph：未加载 / 在途字节的占位字符（中点 U+00B7）。
    // 十六进制面板画两个、ASCII 面板画一个；它不属于 0x20..0x7E，所以不会与任何真实字符混淆。
    // Consolas 与微软雅黑都有该字形（已在本机用 GlyphTypeface 核对）。
    inline constexpr char16_t kLoadingGlyph = 0x00B7;

    // kUnreadableAsciiGlyph：不可读字节在 ASCII 面板里的占位字符（乘号 U+00D7）。
    // 原先用问号，会与真实的 0x3F 字节（'?'）混淆；乘号同样不在可见 ASCII 范围内。
    // Consolas 与微软雅黑都有该字形。十六进制面板里的不可读仍画 "??"：那里只可能出现十六进制数字，没有歧义。
    inline constexpr char16_t kUnreadableAsciiGlyph = 0x00D7;

    // IsPrintableAscii：判断一个字节是否是可见 ASCII（0x20..0x7E）。
    // 传入：字节值；传出：是否可见。
    bool IsPrintableAscii(std::uint8_t value);

    // FormatHexText：大写空格分隔的十六进制，例如 "41 42 43"。
    // 传入：字节序列；传出：文本，空序列返回空串。
    QString FormatHexText(const QByteArray& bytes);

    // FormatAsciiText：按"所见即所得"的 ASCII 文本，不可见字节显示为 '.'。
    // 传入：字节序列；传出：与字节等长的文本。
    QString FormatAsciiText(const QByteArray& bytes);

    // FormatCArray：C 数组初始化列表，例如 "{ 0x41, 0x42, 0x43 }"。
    // 字节数超过 16 时按每行 16 个换行并缩进四个空格，方便直接粘进源码。
    // 传入：字节序列；传出：文本，空序列返回 "{ }"。
    QString FormatCArray(const QByteArray& bytes);

    // FormatPythonBytes：Python bytes 字面量，例如 "b'\x41\x42'"，全部字节都用 \xNN 转义。
    // 传入：字节序列；传出：文本，空序列返回 "b''"。
    QString FormatPythonBytes(const QByteArray& bytes);

    // FormatEscapedString：C 风格转义字符串（带双引号），例如 "\"AB\\x00\""。
    // 可见 ASCII 原样输出（引号与反斜杠加转义），其余用 \xNN；
    // 紧跟在 \xNN 之后的十六进制数字字符也改用 \xNN，避免 C 编译器把它们吞进同一个转义。
    // 传入：字节序列；传出：文本，空序列返回 "\"\""。
    QString FormatEscapedString(const QByteArray& bytes);

    // FormatAddress：地址文本，例如 "0x00007FFF00000000"。
    // 传入：地址、十六进制位数（8 或 16，其余值按实际需要自动补齐到该位数以上）；传出：文本。
    QString FormatAddress(std::uint64_t address, int digits);
    // Split a common prefix so the header is about three characters shorter
    // than the row suffix, leaving room for its arrow. Shared digits beyond
    // that split stay in the rows; a shorter actual common prefix takes priority.
    QString CommonAddressPrefix(std::uint64_t firstRow, std::uint64_t lastRow, int digits);
    QString FormatAddressSuffix(std::uint64_t address, int digits, const QString& prefix);

    // ParseHexText：解析粘贴来的十六进制文本。
    // 容忍：空格、制表符、换行、逗号、分号、花括号作为分隔；每个记号可带 0x/0X 前缀；
    //       记号可以是连续的偶数位十六进制（"4142" 解析为两个字节）。
    // 严格：任何非法字符、奇数位记号、空内容都使整体失败，不返回半截数据。
    // 传入：文本、结果缓冲、错误原因（可为空指针）；传出：是否解析成功。
    bool ParseHexText(const QString& text, QByteArray* bytesOut, QString* errorOut);
}
