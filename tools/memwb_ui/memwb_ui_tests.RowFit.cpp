// memwb_ui_tests.RowFit.cpp
// 作用：HexCanvas "自适应行宽 + 字号缩放 + 最小高度"（内存编辑器自适应大小）的画布层离屏验证：
//   1) 纯函数：RowWidthChars 的手算常量与"和画布真实布局恒等"（防两份公式漂移）；
//      ChooseAutoBytesPerRow 对每个宽度的候选集/非递减/放得下/极大性，与独立的暴力期望逐点对拍；
//   2) 视口驱动：自适应模式下 resize 到各档阈值两侧，行宽等于期望、横向滚动条最大值与是否放得下一致，
//      抓图右侧空白不超过"下一档与当前档的宽度差"，并比固定 16 字节时的空白小；
//   3) 锚点：插入点可见时换行宽它停在同一屏幕行（选区不变），不可见时沿用首行锚点；
//   4) 不重读：换行宽（手动与自动）不发 contentChanged、不换来源代次、不丢已落定的页、
//      新请求只含新露出的页；
//   5) 手动优先：手选关闭自适应、非法值不动标志、同值不发信号、重新开启立即重选、信号参数正确；
//   6) 联动触发：分组、地址位数（含首次装空间）、字号缩放、直接 setFont 都会让行宽重选；
//   7) 纵向：minimumSizeHint 至少表头 + 4 行且不抬宽度，放进很矮的布局时仍有 4 行，可见行数填满视口；
//   8) 字号缩放：级别夹取与信号、cellRect 宽度变化、缩小后首行夹取（无末尾空白带）、
//      Ctrl+滚轮（累计 120 成一档、不滚动内容）、Ctrl+= / Ctrl++ / Ctrl+- / Ctrl+0、无数据时也能缩放。
// 期望值要么手算写死，要么由"独立于产品实现"的暴力写法算出；所有断言都针对一个具体的人为缺陷
// （见各测试函数上的"杀死"说明）。入口 RunRowFitTests 由 memwb_ui_tests.cpp 的 main 调用。

#include "memwb_ui_signals.h"

#include "../../Ksword5.1/Ksword5.1/UI/MemoryWorkbench/HexCanvasFormat.h"
#include "../../Ksword5.1/Ksword5.1/UI/SmoothScrollSupport.h"

#include <QApplication>
#include <QFont>
#include <QFontMetrics>
#include <QScrollBar>
#include <QSignalSpy>
#include <QThread>
#include <QVBoxLayout>
#include <QWheelEvent>
#include <QWidget>

#include <algorithm>
#include <cstdint>
#include <iterator>
#include <optional>
#include <set>
#include <vector>

namespace memwb_test
{
    namespace
    {
        using ks::ui::HexCanvas;
        using Pane = HexCanvas::ActivePane;
        namespace fmt = ks::ui::hexcanvas_format;

        // kRowWidths：行宽候选集（升序）。故意不用产品里的 kAutoBytesPerRowCandidates：
        // 期望值必须独立于被测实现，产品常量少一档时这里才能抓到。
        constexpr int kRowWidths[] = { 8, 16, 32, 48, 64 };

        // kGroups：十六进制分组的全部合法值。
        constexpr int kGroups[] = { 1, 2, 4, 8 };

        // kBase / kSpaceBytes：多数测试的静态数据地址空间 [0x10000, 0x1FFFF]，上界不超过 0xFFFFFFFF，所以地址列是 8 位。
        constexpr std::uint64_t kBase = 0x10000ULL;
        constexpr int kSpaceBytes = 64 * 1024;

        // kDigits：上面这块地址空间的地址列位数。
        constexpr int kDigits = 8;

        // CharWidthOf：画布当前字体下单个等宽字符的像素宽度（与 HexCanvas::rebuildMetrics 同一算法）。
        // 传入：画布；传出：宽度（至少 1）。
        int CharWidthOf(const HexCanvas& canvas)
        {
            return std::max(1, QFontMetrics(canvas.font()).horizontalAdvance(QLatin1Char('0')));
        }

        // ContentWidthOf：画布当前一行内容的像素宽度，由 sizeHint 反推（sizeHint 宽 = 内容宽 + 竖向滚动条宽 + 2）。
        // 传入：画布；传出：内容宽度。
        int ContentWidthOf(const HexCanvas& canvas)
        {
            return canvas.sizeHint().width() - canvas.verticalScrollBar()->sizeHint().width() - 2;
        }

        // ThresholdPx：某一档行宽的内容像素宽度（刚好放得下它所需的最小视口宽度）。
        // 传入：行宽、分组、地址位数、字符宽度；传出：像素。
        int ThresholdPx(int bytesPerRow, int groupSize, int addressDigits, int charWidth)
        {
            return fmt::RowWidthChars(bytesPerRow, groupSize, addressDigits) * charWidth;
        }

        // ExpectedAuto：自适应行宽的期望值，独立于产品实现的写法——从小到大扫描，保留最后一个放得下的；
        // 一个都放不下就是 8。传入：视口宽度、字符宽度、分组、地址位数；传出：期望行宽。
        int ExpectedAuto(int viewportWidth, int charWidth, int groupSize, int addressDigits)
        {
            int best = 8;
            for (const int candidate : kRowWidths)
            {
                if (ThresholdPx(candidate, groupSize, addressDigits, charWidth) <= viewportWidth)
                {
                    best = candidate;
                }
            }
            return best;
        }

        // NextLarger：候选集里比 bytesPerRow 大一档的行宽；已是最大返回 0。
        int NextLarger(int bytesPerRow)
        {
            for (const int candidate : kRowWidths)
            {
                if (candidate > bytesPerRow)
                {
                    return candidate;
                }
            }
            return 0;
        }

        // SetViewportWidth：把画布调整到"视口宽度恰好为 viewportWidth"（画布宽 = 视口宽 + 滚动条等占用），并处理事件。
        // 传入：画布、目标视口宽度、画布高度。调用后视口宽度以 canvas.viewport()->width() 为准。
        void SetViewportWidth(HexCanvas& canvas, int viewportWidth, int height)
        {
            const int frame = canvas.width() - canvas.viewport()->width();
            canvas.resize(viewportWidth + frame, height);
            Flush();
        }

        // RightmostInkX：在 top 行以下找与底色不同的最右像素的 x，没有返回 -1。
        // 传入：图像、起始行、底色；传出：x 坐标。
        int RightmostInkX(const QImage& image, int top, const QColor& background)
        {
            for (int x = image.width() - 1; x >= 0; --x)
            {
                for (int y = top; y < image.height(); ++y)
                {
                    if (image.pixelColor(x, y) != background)
                    {
                        return x;
                    }
                }
            }
            return -1;
        }

        // PagesOf：把记录型提供者从第 from 次请求起的页范围展开成页起点集合。
        // 传入：请求记录、起始下标；传出：页起点集合。
        std::set<std::uint64_t> PagesOf(const std::vector<RecordingProvider::Request>& requests, std::size_t from)
        {
            std::set<std::uint64_t> pages;
            for (std::size_t index = from; index < requests.size(); ++index)
            {
                for (const ks::ui::HexFetchRange& range : requests[index].ranges)
                {
                    for (std::uint64_t page = 0; page < range.pageCount; ++page)
                    {
                        pages.insert(range.firstPageStart + page * 4096ULL);
                    }
                }
            }
            return pages;
        }

        // EnlargedFont：把字体放大一截（点数字体加 4pt，像素字体加 5px），用来直接 setFont 触发 FontChange。
        QFont EnlargedFont(const QFont& font)
        {
            QFont bigger = font;
            if (font.pointSizeF() > 0.0)
            {
                bigger.setPointSizeF(font.pointSizeF() + 4.0);
            }
            else
            {
                bigger.setPixelSize(std::max(1, font.pixelSize()) + 5);
            }
            return bigger;
        }

        // 纯函数：手算常量 + 对每个宽度的候选集/非递减/放得下/极大性 + 与暴力期望逐点对拍。
        // 杀死：RowWidthChars 公式少算中缝/组间隙/边距；ChooseAutoBytesPerRow 选最小而不是最大、
        // 候选集少一档、判据用 < 而不是 <=、一个都放不下时不退 8。
        void TestPureFunctions()
        {
            // 手算常量（对照 recomputeLayout 的公式逐项算过：1+地址位数+2+十六进制区+2+ASCII 区+1）。
            CHECK(fmt::RowWidthChars(8, 1, 8) == 45);
            CHECK(fmt::RowWidthChars(16, 1, 8) == 79);
            CHECK(fmt::RowWidthChars(16, 1, 16) == 87);
            CHECK(fmt::RowWidthChars(32, 1, 16) == 155);
            CHECK(fmt::RowWidthChars(48, 1, 16) == 223);
            CHECK(fmt::RowWidthChars(64, 1, 16) == 291);
            CHECK(fmt::RowWidthChars(16, 2, 16) == 93);     // 2 字节一组：偶数列多 1 个字符，8 字节中缝多 2 个
            CHECK(fmt::RowWidthChars(16, 4, 16) == 89);
            CHECK(fmt::RowWidthChars(16, 8, 16) == 87);     // 8 字节一组与中缝重合，等同 1 字节一组
            CHECK(fmt::RowWidthChars(0, 1, 16) == 0);       // 非法行宽返回 0

            for (const int group : kGroups)
            {
                for (const int digits : { 8, 16 })
                {
                    for (const int charWidth : { 5, 6, 7, 9, 12 })
                    {
                        // 逐宽度扫描：每条性质各记一个"第一处违反的宽度"，扫完一次性断言（避免十几万条断言）。
                        int previous = 0;
                        int badSet = -1;
                        int badMonotonic = -1;
                        int badFits = -1;
                        int badMaximal = -1;
                        int badBrute = -1;
                        for (int width = 0; width <= 3000; ++width)
                        {
                            const int chosen = fmt::ChooseAutoBytesPerRow(width, charWidth, group, digits);
                            const bool inSet = std::find(std::begin(kRowWidths), std::end(kRowWidths), chosen) != std::end(kRowWidths);
                            if (!inSet && badSet < 0)
                            {
                                badSet = width;
                            }
                            if (chosen < previous && badMonotonic < 0)
                            {
                                badMonotonic = width;
                            }
                            previous = chosen;

                            // 放得下：选出的档内容宽度不超过视口；只有一个都放不下时才允许退到 8 而超宽。
                            const bool fits = ThresholdPx(chosen, group, digits, charWidth) <= width;
                            if (!fits && chosen != 8 && badFits < 0)
                            {
                                badFits = width;
                            }

                            // 极大性：更大的一档必然放不下。
                            const int larger = NextLarger(chosen);
                            if (larger != 0 && ThresholdPx(larger, group, digits, charWidth) <= width && badMaximal < 0)
                            {
                                badMaximal = width;
                            }

                            // 与独立暴力期望逐点对拍（含"一个都放不下返回 8"）。
                            if (chosen != ExpectedAuto(width, charWidth, group, digits) && badBrute < 0)
                            {
                                badBrute = width;
                            }
                        }
                        const QString where = QStringLiteral("分组 %1 地址位数 %2 字符宽 %3").arg(group).arg(digits).arg(charWidth);
                        CHECK_NOTE(badSet < 0, where + QStringLiteral("：宽度 %1 选出的行宽不在候选集里").arg(badSet));
                        CHECK_NOTE(badMonotonic < 0, where + QStringLiteral("：宽度 %1 处行宽变小了（应随宽度非递减）").arg(badMonotonic));
                        CHECK_NOTE(badFits < 0, where + QStringLiteral("：宽度 %1 选出的档放不下却不是 8").arg(badFits));
                        CHECK_NOTE(badMaximal < 0, where + QStringLiteral("：宽度 %1 选出的档不是最大的放得下的一档").arg(badMaximal));
                        CHECK_NOTE(badBrute < 0, where + QStringLiteral("：宽度 %1 与暴力期望不一致").arg(badBrute));

                        // 极窄：一档都放不下，退 8（横向滚动条兜底）。
                        CHECK(fmt::ChooseAutoBytesPerRow(0, charWidth, group, digits) == 8);
                        CHECK(fmt::ChooseAutoBytesPerRow(ThresholdPx(8, group, digits, charWidth) - 1, charWidth, group, digits) == 8);
                        // 极宽：最大一档。
                        CHECK(fmt::ChooseAutoBytesPerRow(100000, charWidth, group, digits) == 64);
                    }
                }
            }
        }

        // 画布真实布局与纯函数恒等：内容宽度 == RowWidthChars * 字符宽度（五档行宽 x 四种分组 x 两种地址位数，
        // 缩放字号后再核对一遍）。杀死：RowWidthChars 与 recomputeLayout 的公式漂移。
        void TestLayoutIdentity()
        {
            ApplyTheme(false);
            HexCanvas canvas;
            canvas.resize(900, 420);
            canvas.show();
            for (const int digits : { 8, 16 })
            {
                // 上界 <= 0xFFFFFFFF 是 8 位地址列，否则 16 位。
                CHECK(canvas.setAddressSpace(0, digits == 8 ? 0xFFFFFULL : 0x100000000ULL));
                for (const int group : kGroups)
                {
                    CHECK(canvas.setGroupSize(group));
                    for (const int bytesPerRow : kRowWidths)
                    {
                        CHECK(canvas.setBytesPerRow(bytesPerRow));
                        CHECK_NOTE(
                            ContentWidthOf(canvas) == fmt::RowWidthChars(bytesPerRow, group, digits) * CharWidthOf(canvas),
                            QStringLiteral("行宽 %1 分组 %2 地址位数 %3：真实内容宽 %4，公式 %5")
                                .arg(bytesPerRow).arg(group).arg(digits).arg(ContentWidthOf(canvas))
                                .arg(fmt::RowWidthChars(bytesPerRow, group, digits) * CharWidthOf(canvas)));
                    }
                }
            }

            // 放大字号后字符宽度变了，恒等式仍成立（字符宽度这一项也被固定）。
            canvas.zoomBy(3);
            CHECK(canvas.setGroupSize(2));
            CHECK(canvas.setBytesPerRow(48));
            CHECK(ContentWidthOf(canvas) == fmt::RowWidthChars(48, 2, 16) * CharWidthOf(canvas));
        }

        // 视口驱动：自适应模式下 resize 到各档阈值两侧，行宽等于期望；足够宽时横向滚动条最大值为 0；
        // 抓图右侧空白不超过"下一档与当前档的内容宽度差"，并比固定 16 字节时的空白小。
        // 杀死：选最小行宽、选宽度时不用视口宽度（用控件宽度）、不算地址位数、候选集少一档、
        // resize 不触发重选。
        void TestViewportDrivesRowWidth()
        {
            ApplyTheme(false);
            auto fixture = MakeStaticFixture(kBase, MakePattern(kSpaceBytes), false, QSize(900, 420));
            HexCanvas& canvas = *fixture->canvas;
            CHECK(!canvas.isAutoBytesPerRow());     // 画布默认不是自适应
            CHECK(canvas.bytesPerRow() == 16);
            CHECK(canvas.groupSize() == 1);
            CHECK(ContentWidthOf(canvas) == ThresholdPx(16, 1, kDigits, CharWidthOf(canvas)));  // 前置：地址列确实是 8 位
            const int charWidth = CharWidthOf(canvas);

            // 没开自适应：怎么改宽度行宽都不动。
            SetViewportWidth(canvas, 2400, 420);
            CHECK(canvas.bytesPerRow() == 16);
            canvas.setAutoBytesPerRow(true);
            CHECK(canvas.isAutoBytesPerRow());

            // 阈值两侧各取一点 + 极窄 + 极宽：五档都要出现。
            std::vector<int> widths = { 100, 160 };
            for (const int bytesPerRow : kRowWidths)
            {
                const int threshold = ThresholdPx(bytesPerRow, 1, kDigits, charWidth);
                widths.push_back(threshold - 1);
                widths.push_back(threshold);
                widths.push_back(threshold + 1);
            }
            widths.push_back(ThresholdPx(64, 1, kDigits, charWidth) + 400);
            std::set<int> seen;
            for (const int target : widths)
            {
                SetViewportWidth(canvas, target, 420);
                const int viewportWidth = canvas.viewport()->width();
                const int expected = ExpectedAuto(viewportWidth, charWidth, 1, kDigits);
                CHECK_NOTE(
                    canvas.bytesPerRow() == expected,
                    QStringLiteral("视口宽 %1：行宽应为 %2，实际 %3").arg(viewportWidth).arg(expected).arg(canvas.bytesPerRow()));
                const bool smallestFits = ThresholdPx(8, 1, kDigits, charWidth) <= viewportWidth;
                if (smallestFits)
                {
                    CHECK_NOTE(
                        canvas.horizontalScrollBar()->maximum() == 0,
                        QStringLiteral("视口宽 %1 放得下，横向滚动条最大值应为 0，实际 %2")
                            .arg(viewportWidth).arg(canvas.horizontalScrollBar()->maximum()));
                }
                else
                {
                    CHECK_NOTE(
                        canvas.horizontalScrollBar()->maximum() > 0,
                        QStringLiteral("视口宽 %1 连 8 字节一行都放不下，应出横向滚动条").arg(viewportWidth));
                }
                seen.insert(canvas.bytesPerRow());
            }
            CHECK_NOTE(seen.size() == 5, QStringLiteral("五档行宽都应出现过，实际 %1 档").arg(seen.size()));

            // 抓图：右侧空白不超过下一档与当前档的内容宽度差（再加两个字符的容差），并比固定 16 字节小。
            const QColor surface = KswordTheme::SurfaceColor();
            const int bodyTop = canvas.cellRect(kBase, Pane::Hex).y() + 1;
            for (const int bytesPerRow : { 16, 32, 48 })
            {
                SetViewportWidth(canvas, ThresholdPx(bytesPerRow, 1, kDigits, charWidth) + 50, 420);
                const int viewportWidth = canvas.viewport()->width();
                CHECK(canvas.bytesPerRow() == bytesPerRow);
                const QImage image = GrabImage(canvas);
                const int rightmost = RightmostInkX(image, bodyTop, surface);
                CHECK_NOTE(rightmost > viewportWidth / 2, QStringLiteral("内容应铺过视口一半，最右字迹 x=%1，视口宽 %2").arg(rightmost).arg(viewportWidth));
                const int blank = viewportWidth - 1 - rightmost;
                const int next = NextLarger(bytesPerRow);
                const int allowed = (fmt::RowWidthChars(next, 1, kDigits) - fmt::RowWidthChars(bytesPerRow, 1, kDigits)) * charWidth
                    + 2 * charWidth;
                CHECK_NOTE(
                    blank <= allowed,
                    QStringLiteral("行宽 %1：右侧空白 %2 超过允许的 %3").arg(bytesPerRow).arg(blank).arg(allowed));

                // 与固定 16 字节对照：行宽大于 16 时自适应的空白必须明显更小。
                if (bytesPerRow > 16)
                {
                    CHECK(canvas.setBytesPerRow(16));
                    const int blankFixed = viewportWidth - 1 - RightmostInkX(GrabImage(canvas), bodyTop, surface);
                    CHECK_NOTE(blankFixed > blank, QStringLiteral("固定 16 字节空白 %1 应大于自适应空白 %2").arg(blankFixed).arg(blank));
                    canvas.setAutoBytesPerRow(true);
                    CHECK(canvas.bytesPerRow() == bytesPerRow);
                }
            }
        }

        // 锚点：插入点可见时换行宽它停在同一屏幕行（含选区不变）；不可见时沿用首行锚点。
        // 杀死：锚点用首行而不是插入点；选区/插入点被改动；不可见分支改了旧行为。
        void TestAnchor()
        {
            ApplyTheme(false);
            auto fixture = MakeStaticFixture(kBase, MakePattern(kSpaceBytes), false, QSize(1500, 360));
            HexCanvas& canvas = *fixture->canvas;

            // 插入点所在行在屏幕第 5 行（相对首行），选区是 8 个字节，插入点在选区末端。
            const std::uint64_t anchorAddress = kBase + 0x4000ULL + 3ULL;
            canvas.setFirstVisibleRow(1019);
            canvas.setCaretAddress(anchorAddress, false, false);
            canvas.setCaretAddress(anchorAddress + 7ULL, true, false);
            const std::uint64_t caret = canvas.caretAddress();
            CHECK(caret == anchorAddress + 7ULL);
            const std::optional<HexCanvas::AddressRange> selection = canvas.selectedRange();
            CHECK(selection.has_value());
            const QRect before = canvas.cellRect(caret, Pane::Hex);
            CHECK(!before.isNull());
            for (const int bytesPerRow : { 32, 64, 8, 48, 16 })
            {
                CHECK(canvas.setBytesPerRow(bytesPerRow));
                const QRect after = canvas.cellRect(caret, Pane::Hex);
                CHECK_NOTE(!after.isNull(), QStringLiteral("行宽 %1：插入点应仍可见").arg(bytesPerRow));
                CHECK_NOTE(
                    after.y() == before.y(),
                    QStringLiteral("行宽 %1：插入点应停在同一屏幕行（y %2 -> %3）").arg(bytesPerRow).arg(before.y()).arg(after.y()));
                CHECK(canvas.caretAddress() == caret);
                const std::optional<HexCanvas::AddressRange> after_selection = canvas.selectedRange();
                CHECK(after_selection.has_value() && selection.has_value()
                    && after_selection->first == selection->first && after_selection->last == selection->last);
            }

            // 插入点落在"被截断的半行"上（相对首行恰好等于完整可见行数）：它不算完整可见，必须沿用首行锚点。
            // 判据差一（< 写成 <=）会把它当锚点，换行宽后首行被算成"插入点新行 - 完整可见行数"，与首行锚点的结果不同。
            for (const int bytesPerRow : { 32, 64 })
            {
                auto partial = MakeStaticFixture(kBase, MakePattern(kSpaceBytes), false, QSize(1500, 360));
                HexCanvas& other = *partial->canvas;
                other.setFirstVisibleRow(100);
                CHECK(other.firstVisibleRow() == 100);
                // 量出行高与表头高，算出视口里完整可见的行数；再保证末尾确实有一条被截断的半行（不够整行高度的余量）。
                const QRect firstCell = other.cellRect(kBase + 100ULL * 16ULL, Pane::Hex);
                CHECK(!firstCell.isNull());
                const int rowHeight = firstCell.height();
                const int headerHeight = firstCell.y();
                int remainder = (other.viewport()->height() - headerHeight) % rowHeight;
                if (remainder == 0)
                {
                    // 恰好整除：把画布加高半行，制造出被截断的半行。
                    other.resize(other.width(), other.height() + rowHeight / 2);
                    QApplication::processEvents();
                    remainder = (other.viewport()->height() - headerHeight) % rowHeight;
                }
                CHECK_NOTE(remainder > 0, QStringLiteral("前置：视口末尾应有被截断的半行（余量 %1）").arg(remainder));
                const std::uint64_t fullRows = other.visibleRowCount();
                CHECK_NOTE(fullRows >= 4, QStringLiteral("前置：完整可见行数应不少于 4，实际 %1").arg(fullRows));
                // 插入点放在首行之后第 fullRows 行（即被截断的那一行）。
                const std::uint64_t truncatedRowAddress = kBase + (100ULL + fullRows) * 16ULL;
                other.setCaretAddress(truncatedRowAddress, false, false);
                CHECK(other.firstVisibleRow() == 100);          // 前置：没有因为设插入点而滚动
                CHECK(other.setBytesPerRow(bytesPerRow));
                const std::uint64_t rowBytes = static_cast<std::uint64_t>(bytesPerRow);
                const std::uint64_t rowBase = kBase - (kBase % rowBytes);
                const std::uint64_t expectedRow = (kBase + 100ULL * 16ULL - rowBase) / rowBytes;
                CHECK_NOTE(
                    other.firstVisibleRow() == expectedRow,
                    QStringLiteral("行宽 %1：插入点在被截断的半行时应沿用首行锚点（首行 %2），实际 %3")
                        .arg(bytesPerRow).arg(expectedRow).arg(other.firstVisibleRow()));
            }

            // 插入点不可见（首行滚到 40，插入点还在地址空间起点）：沿用首行锚点，换算出的首行等于
            // 旧首行起始地址在新行宽下所在的行（与旧测试 TestBytesPerRowAndGroup 同一语义）。
            for (const int bytesPerRow : { 32, 8, 64, 48 })
            {
                auto hidden = MakeStaticFixture(kBase, MakePattern(kSpaceBytes), false, QSize(1500, 360));
                HexCanvas& other = *hidden->canvas;
                other.setFirstVisibleRow(40);
                CHECK(other.firstVisibleRow() == 40);
                CHECK(other.setBytesPerRow(bytesPerRow));
                const std::uint64_t rowBase = kBase - (kBase % static_cast<std::uint64_t>(bytesPerRow));
                const std::uint64_t expectedRow = (kBase + 40ULL * 16ULL - rowBase) / static_cast<std::uint64_t>(bytesPerRow);
                CHECK_NOTE(
                    other.firstVisibleRow() == expectedRow,
                    QStringLiteral("行宽 %1：首行锚点应换算成第 %2 行，实际 %3")
                        .arg(bytesPerRow).arg(expectedRow).arg(other.firstVisibleRow()));
            }
        }

        // 不重读：换行宽（手动与自动、窗口变宽变窄）不发 contentChanged、不换来源代次、已落定的页不减少、
        // 新请求只含新露出的页（旧页不重复请求）。杀死：换行宽时误调 refresh()。
        void TestNoRereadOnRowWidthChange()
        {
            ApplyTheme(false);
            constexpr std::uint64_t kFirst = 0x100000ULL;
            constexpr std::uint64_t kLast = kFirst + 64ULL * 4096ULL - 1ULL;
            auto holder = MakeAsyncCanvas(kFirst, kLast, false, false);
            HexCanvas& canvas = *holder->canvas;

            // 先滚到第 2000 行（16 字节一行时是偏移 32000，落在第 7 页），让可见页远离空间起点；
            // 再让第 6、7、8 页落定，建立基线：来源代次、已落定页集合、已请求过的页集合、contentChanged 计数。
            // 换成 64 字节一行后可见范围变成约 1.4 KB，会跨进第 8 页、预取窗口随之外扩到第 10 页——
            // 第 10 页是"新露出的页"，所以手动那一步一定有新请求（见 verify 的 expectNew）。
            canvas.setFirstVisibleRow(2000);
            for (std::uint64_t index = 0; index < 3; ++index)
            {
                CHECK(DeliverPage(canvas, kFirst + (6ULL + index) * 4096ULL) == HexCanvas::PageResult::Accepted);
            }
            Flush();
            QSignalSpy contentSpy(&canvas, &HexCanvas::contentChanged);
            const std::uint64_t revision = canvas.sourceRevision();
            const std::set<std::uint64_t> settledBefore = canvas.settledPageStartsInRange(kFirst, kLast);
            CHECK(settledBefore.size() == 3);
            std::set<std::uint64_t> requestedSoFar = PagesOf(holder->provider.requests, 0);
            std::size_t requestsSeen = holder->provider.requests.size();
            CHECK(!requestedSoFar.empty());

            // verify：每一步操作之后核对四件事；expectNew 为真时还要求确实发出了新请求（证明"新请求"检查不是空转）。
            const auto verify = [&](const QString& step, bool expectNew) {
                Flush();
                CHECK_NOTE(contentSpy.count() == 0, step + QStringLiteral("：改行宽不得发 contentChanged"));
                CHECK_NOTE(canvas.sourceRevision() == revision, step + QStringLiteral("：改行宽不得换来源代次"));
                CHECK_NOTE(
                    canvas.settledPageStartsInRange(kFirst, kLast) == settledBefore,
                    step + QStringLiteral("：已落定的页不得减少或变化"));
                const std::set<std::uint64_t> fresh = PagesOf(holder->provider.requests, requestsSeen);
                if (expectNew)
                {
                    CHECK_NOTE(!fresh.empty(), step + QStringLiteral("：可见范围外扩，应有新露出的页被请求"));
                }
                for (const std::uint64_t page : fresh)
                {
                    CHECK_NOTE(requestedSoFar.count(page) == 0, step + QStringLiteral("：页 0x%1 被重复请求").arg(page, 0, 16));
                }
                requestedSoFar.insert(fresh.begin(), fresh.end());
                requestsSeen = holder->provider.requests.size();
            };

            // 手动：16 -> 64（每行 4 倍的字节，可见范围变大，会露出新页）。
            CHECK(canvas.setBytesPerRow(64));
            verify(QStringLiteral("手动 64"), true);

            // 自动：先按 900 宽重选（64 -> 16），再变宽到 2400（-> 64），再变窄到 700。
            canvas.setAutoBytesPerRow(true);
            verify(QStringLiteral("开启自适应"), false);
            SetViewportWidth(canvas, 2400, 420);
            verify(QStringLiteral("自适应变宽"), false);
            SetViewportWidth(canvas, 700, 420);
            verify(QStringLiteral("自适应变窄"), false);
        }

        // 手动优先：手选关闭自适应；非法值返回 false 且不动标志；同值不发信号；重新开启立即重选；
        // 自适应下手选恰好等于当前档也要关闭自适应；信号参数正确。
        // 杀死：手动 setBytesPerRow 不清 auto 标志；"同值早返回"放在清标志之前；非法值清了标志；信号漏发/多发。
        void TestManualBeatsAuto()
        {
            ApplyTheme(false);
            auto fixture = MakeStaticFixture(kBase, MakePattern(kSpaceBytes), false, QSize(900, 420));
            HexCanvas& canvas = *fixture->canvas;
            QSignalSpy modeSpy(&canvas, &HexCanvas::rowWidthModeChanged);
            const int charWidth = CharWidthOf(canvas);

            // 开启自适应：宽度够 64，行宽 16 -> 64，恰好发一次 (64, true)。
            SetViewportWidth(canvas, ThresholdPx(64, 1, kDigits, charWidth) + 100, 420);
            CHECK(modeSpy.count() == 0);
            canvas.setAutoBytesPerRow(true);
            CHECK(canvas.isAutoBytesPerRow());
            CHECK(canvas.bytesPerRow() == 64);
            CHECK(modeSpy.count() == 1);
            CHECK(modeSpy.count() == 1 && modeSpy.at(0).at(0).toInt() == 64 && modeSpy.at(0).at(1).toBool());

            // 非法值：返回 false，不改行宽，不清自适应标志，不发信号。
            CHECK(!canvas.setBytesPerRow(24));
            CHECK(canvas.isAutoBytesPerRow());
            CHECK(canvas.bytesPerRow() == 64);
            CHECK(modeSpy.count() == 1);

            // 手选 48：自适应被关闭，发一次 (48, false)。
            CHECK(canvas.setBytesPerRow(48));
            CHECK(!canvas.isAutoBytesPerRow());
            CHECK(canvas.bytesPerRow() == 48);
            CHECK(modeSpy.count() == 2);
            CHECK(modeSpy.count() == 2 && modeSpy.at(1).at(0).toInt() == 48 && !modeSpy.at(1).at(1).toBool());

            // 再怎么改宽度也不换档。
            SetViewportWidth(canvas, ThresholdPx(64, 1, kDigits, charWidth) + 600, 420);
            CHECK(canvas.bytesPerRow() == 48);
            SetViewportWidth(canvas, 300, 420);
            CHECK(canvas.bytesPerRow() == 48);
            CHECK(modeSpy.count() == 2);

            // 同值再设、关闭已关闭的自适应：都不发信号。
            CHECK(canvas.setBytesPerRow(48));
            canvas.setAutoBytesPerRow(false);
            CHECK(modeSpy.count() == 2);

            // 重新开启：立即按当前宽度重选（宽度只够 32），发 (32, true)。
            SetViewportWidth(canvas, ThresholdPx(32, 1, kDigits, charWidth) + 10, 420);
            CHECK(canvas.bytesPerRow() == 48);      // 自适应还没开，行宽不动
            canvas.setAutoBytesPerRow(true);
            CHECK(canvas.bytesPerRow() == ExpectedAuto(canvas.viewport()->width(), charWidth, 1, kDigits));
            CHECK(canvas.bytesPerRow() == 32);
            CHECK(modeSpy.count() == 3);
            CHECK(modeSpy.count() == 3 && modeSpy.at(2).at(0).toInt() == 32 && modeSpy.at(2).at(1).toBool());

            // 自适应下手选恰好等于当前档：行宽没变，但模式变了——必须关闭自适应并发 (32, false)。
            CHECK(canvas.setBytesPerRow(32));
            CHECK(!canvas.isAutoBytesPerRow());
            CHECK(modeSpy.count() == 4);
            CHECK(modeSpy.count() == 4 && modeSpy.at(3).at(0).toInt() == 32 && !modeSpy.at(3).at(1).toBool());
            SetViewportWidth(canvas, ThresholdPx(64, 1, kDigits, charWidth) + 100, 420);
            CHECK(canvas.bytesPerRow() == 32);      // 窗口变宽也不再自动换档
        }

        // 联动触发：分组、地址位数（含首次装空间）、字号缩放、直接 setFont 都让自适应重选行宽。
        // 每个场景都把视口宽度精确卡在 32 字节一行的阈值上：变化之后 32 一定放不下，必然换档。
        // 杀死：setGroupSize / installSpace / changeEvent(FontChange) 里漏调自适应；字体变化分支漏调。
        void TestLinkedTriggers()
        {
            ApplyTheme(false);

            // 分组：1 字节一组时 32 刚好放得下，2 字节一组多出 12 个字符，放不下 -> 16。
            {
                auto fixture = MakeStaticFixture(kBase, MakePattern(kSpaceBytes), false, QSize(900, 420));
                HexCanvas& canvas = *fixture->canvas;
                const int charWidth = CharWidthOf(canvas);
                canvas.setAutoBytesPerRow(true);
                SetViewportWidth(canvas, ThresholdPx(32, 1, kDigits, charWidth), 420);
                CHECK(canvas.bytesPerRow() == 32);
                CHECK(canvas.setGroupSize(2));
                CHECK(canvas.bytesPerRow() == ExpectedAuto(canvas.viewport()->width(), charWidth, 2, kDigits));
                CHECK_NOTE(canvas.bytesPerRow() == 16, QStringLiteral("2 字节一组时 32 放不下，应退到 16，实际 %1").arg(canvas.bytesPerRow()));
                CHECK(canvas.setGroupSize(1));
                CHECK(canvas.bytesPerRow() == 32);
            }

            // 地址位数：8 位地址列时 32 刚好放得下，空间上界超过 32 位后地址列变 16 位（多 8 个字符）-> 16；
            // 换回去又是 32。走的是 installSpace 路径。
            {
                auto holder = MakeAsyncCanvas(0x10000ULL, 0x1FFFFULL, false, false);
                HexCanvas& canvas = *holder->canvas;
                const int charWidth = CharWidthOf(canvas);
                canvas.setAutoBytesPerRow(true);
                SetViewportWidth(canvas, ThresholdPx(32, 1, 8, charWidth), 420);
                CHECK(canvas.bytesPerRow() == 32);
                CHECK(canvas.setAddressSpace(0x10000ULL, 1ULL << 47));
                CHECK_NOTE(
                    canvas.bytesPerRow() == ExpectedAuto(canvas.viewport()->width(), charWidth, 1, 16),
                    QStringLiteral("16 位地址列下行宽应为 %1，实际 %2")
                        .arg(ExpectedAuto(canvas.viewport()->width(), charWidth, 1, 16)).arg(canvas.bytesPerRow()));
                CHECK(canvas.bytesPerRow() == 16);
                CHECK(canvas.setAddressSpace(0x10000ULL, 0x1FFFFULL));
                CHECK(canvas.bytesPerRow() == 32);
            }

            // 首次装空间：先开自适应（还没有地址空间，只记标志），装空间时按视口宽度选档。
            {
                HexCanvas canvas;
                RecordingProvider provider;
                canvas.resize(900, 420);
                canvas.show();
                canvas.setPageProvider(&provider);
                QSignalSpy modeSpy(&canvas, &HexCanvas::rowWidthModeChanged);
                const int charWidth = CharWidthOf(canvas);
                canvas.setAutoBytesPerRow(true);
                CHECK(canvas.isAutoBytesPerRow());
                CHECK(canvas.bytesPerRow() == 16);      // 没有地址空间，行宽不动
                CHECK(modeSpy.count() == 1);            // 模式变了发一次
                SetViewportWidth(canvas, ThresholdPx(48, 1, kDigits, charWidth) + 5, 420);
                CHECK(canvas.bytesPerRow() == 16);      // 仍然没有地址空间
                CHECK(canvas.setAddressSpace(0x10000ULL, 0x1FFFFULL));
                CHECK_NOTE(
                    canvas.bytesPerRow() == ExpectedAuto(canvas.viewport()->width(), charWidth, 1, kDigits),
                    QStringLiteral("装空间后行宽应为 %1，实际 %2")
                        .arg(ExpectedAuto(canvas.viewport()->width(), charWidth, 1, kDigits)).arg(canvas.bytesPerRow()));
                CHECK(canvas.bytesPerRow() == 48);
            }

            // 字号缩放：放大后字符变宽，32 放不下 -> 换档；复位后回到 32。
            {
                auto fixture = MakeStaticFixture(kBase, MakePattern(kSpaceBytes), false, QSize(900, 420));
                HexCanvas& canvas = *fixture->canvas;
                const int charWidth = CharWidthOf(canvas);
                canvas.setAutoBytesPerRow(true);
                SetViewportWidth(canvas, ThresholdPx(32, 1, kDigits, charWidth), 420);
                CHECK(canvas.bytesPerRow() == 32);
                canvas.zoomBy(4);
                const int zoomedWidth = CharWidthOf(canvas);
                CHECK_NOTE(zoomedWidth > charWidth, QStringLiteral("放大 4 档后字符宽度应变大（%1 -> %2）").arg(charWidth).arg(zoomedWidth));
                CHECK_NOTE(
                    canvas.bytesPerRow() == ExpectedAuto(canvas.viewport()->width(), zoomedWidth, 1, kDigits),
                    QStringLiteral("放大后行宽应为 %1，实际 %2")
                        .arg(ExpectedAuto(canvas.viewport()->width(), zoomedWidth, 1, kDigits)).arg(canvas.bytesPerRow()));
                CHECK(canvas.bytesPerRow() < 32);
                canvas.zoomReset();
                CHECK(canvas.bytesPerRow() == 32);
            }

            // 直接 setFont（不经缩放接口）：同样走 FontChange 分支。
            {
                auto fixture = MakeStaticFixture(kBase, MakePattern(kSpaceBytes), false, QSize(900, 420));
                HexCanvas& canvas = *fixture->canvas;
                const int charWidth = CharWidthOf(canvas);
                canvas.setAutoBytesPerRow(true);
                SetViewportWidth(canvas, ThresholdPx(32, 1, kDigits, charWidth), 420);
                CHECK(canvas.bytesPerRow() == 32);
                canvas.setFont(EnlargedFont(canvas.font()));
                const int enlargedWidth = CharWidthOf(canvas);
                CHECK_NOTE(enlargedWidth > charWidth, QStringLiteral("放大字体后字符宽度应变大（%1 -> %2）").arg(charWidth).arg(enlargedWidth));
                CHECK(canvas.bytesPerRow() == ExpectedAuto(canvas.viewport()->width(), enlargedWidth, 1, kDigits));
                CHECK(canvas.bytesPerRow() < 32);
            }
        }

        // 纵向：minimumSizeHint 至少表头 + 4 行且不抬宽度；放进很矮的布局时仍有 4 行；可见行数填满视口。
        // 杀死：没有覆盖 minimumSizeHint（基类只有约 70px）；最小宽度被抬高；高度不到 4 行。
        void TestVerticalMinimum()
        {
            ApplyTheme(false);
            auto fixture = MakeStaticFixture(kBase, MakePattern(kSpaceBytes), false, QSize(900, 420));
            HexCanvas& canvas = *fixture->canvas;
            const int headerHeight = canvas.cellRect(kBase, Pane::Hex).y();
            const int rowHeight = canvas.cellRect(kBase + 16ULL, Pane::Hex).y() - headerHeight;
            CHECK(headerHeight > 0 && rowHeight > 0);

            // 最小高度：表头 + 4 行，且小于表头 + 8 行（不是随便抬得很高）；宽度不抬高，首选尺寸仍是整行宽。
            const QSize minimum = canvas.minimumSizeHint();
            CHECK_NOTE(
                minimum.height() >= headerHeight + 4 * rowHeight,
                QStringLiteral("最小高度 %1 应不小于表头 + 4 行 = %2").arg(minimum.height()).arg(headerHeight + 4 * rowHeight));
            CHECK_NOTE(
                minimum.height() < headerHeight + 8 * rowHeight,
                QStringLiteral("最小高度 %1 不应抬到 8 行以上（%2）").arg(minimum.height()).arg(headerHeight + 8 * rowHeight));
            CHECK_NOTE(minimum.width() <= 200, QStringLiteral("最小宽度 %1 不应被抬高").arg(minimum.width()));
            CHECK(canvas.sizeHint().width() > minimum.width());
            CHECK(canvas.sizeHint().height() > minimum.height());

            // 放进很矮的布局：布局不会把它压到 4 行以下，仍然正常绘制。
            {
                QWidget host;
                QVBoxLayout layout(&host);
                layout.setContentsMargins(0, 0, 0, 0);
                HexCanvas inner;
                layout.addWidget(&inner);
                host.resize(600, 60);
                host.show();
                inner.setStaticData(0x1000, MakePattern(4096));
                QApplication::processEvents();
                CHECK_NOTE(
                    host.height() >= inner.minimumSizeHint().height(),
                    QStringLiteral("宿主高度 %1 应不小于画布最小高度 %2").arg(host.height()).arg(inner.minimumSizeHint().height()));
                CHECK_NOTE(inner.visibleRowCount() >= 4, QStringLiteral("很矮的布局里仍应有 4 行，实际 %1").arg(inner.visibleRowCount()));
                const QImage image = GrabImage(inner);
                CHECK(!image.isNull());
                CHECK_NOTE(inner.lastPaintedRowCount() >= 4, QStringLiteral("应绘制至少 4 行，实际 %1").arg(inner.lastPaintedRowCount()));
            }

            // 吃满：完整可见行占用的高度与视口高度相差不到一行。
            for (const int height : { 200, 301, 420 })
            {
                canvas.resize(900, height);
                Flush();
                const int viewportHeight = canvas.viewport()->height();
                const int used = headerHeight + static_cast<int>(canvas.visibleRowCount()) * rowHeight;
                CHECK_NOTE(
                    used <= viewportHeight && viewportHeight - used < rowHeight,
                    QStringLiteral("高度 %1：已用 %2，视口 %3，相差应小于一行（%4）").arg(height).arg(used).arg(viewportHeight).arg(rowHeight));
            }
        }

        // SendWheel：向画布视口发送一个纵向滚轮事件（angleY 为纵向角度，120 = 一档；modifiers 为按下的修饰键）。
        // 与 TestScrollMapping 同一构造形式，经 QApplication::sendEvent 走真实的事件分发。
        void SendWheel(HexCanvas& canvas, int angleY, Qt::KeyboardModifiers modifiers)
        {
            QWheelEvent wheel(
                QPointF(50, 50), QPointF(50, 50), QPoint(0, 0), QPoint(0, angleY),
                Qt::NoButton, modifiers, Qt::NoScrollPhase, false);
            QApplication::sendEvent(canvas.viewport(), &wheel);
        }

        // TestWheelUnderGlobalSmoothScroll：装上主程序同款全局平滑滚动过滤器后，一档普通滚轮必须只滚 3 行。
        // 真机反馈"一滚动就是一整页"的根因：过滤器把滚动条单位当像素，而本画布竖向滚动条的单位是"行"
        // （singleStep=1、pageStep=可见行数），一档滚轮被换算成 clamp(singleStep*3,48,120)=48 个单位、再被限幅到
        // pageStep 减一行重叠——约一整页的行数。画布设置 ksword_disable_smooth_scroll 退出过滤器后，事件才会走到
        // 画布自己的 wheelEvent（每档 3 行）。前面的 Ctrl+滚轮/键盘缩放测试没装过滤器，抓不到这个问题。
        // 杀死：去掉画布构造里的 setProperty("ksword_disable_smooth_scroll")；把 wheelEvent 的步长改回大步。
        void TestWheelUnderGlobalSmoothScroll()
        {
            ApplyTheme(false);
            QApplication* application = qobject_cast<QApplication*>(QCoreApplication::instance());
            CHECK(application != nullptr);
            if (application == nullptr)
            {
                return;
            }
            ks::ui::InstallGlobalSmoothScrollSupport(application);
            ks::ui::SetGlobalSmoothScrollingEnabled(true);

            auto fixture = MakeStaticFixture(kBase, MakePattern(kSpaceBytes), false, QSize(1500, 420));
            HexCanvas& canvas = *fixture->canvas;
            // 前置：视口里要能显示相当多的行，否则"一页"与"3 行"分不开。
            CHECK_NOTE(canvas.visibleRowCount() >= 12, QStringLiteral("前置：可见行数应不少于 12，实际 %1").arg(canvas.visibleRowCount()));
            CHECK(canvas.property("ksword_disable_smooth_scroll").toBool());

            canvas.setFirstVisibleRow(200);
            // 平滑滚动动画最长约 180ms；多泵一会儿，保证（若被过滤器接管的）动画已经走完。
            const auto settle = []() {
                for (int i = 0; i < 12; ++i)
                {
                    QApplication::processEvents();
                    QThread::msleep(60);
                }
            };
            SendWheel(canvas, -120, Qt::NoModifier);
            settle();
            CHECK_NOTE(
                canvas.firstVisibleRow() == 203,
                QStringLiteral("一档滚轮向下应滚 3 行（200->203），实际 %1——被全局平滑滚动按一整页处理了？").arg(canvas.firstVisibleRow()));
            SendWheel(canvas, 120, Qt::NoModifier);
            settle();
            CHECK_NOTE(canvas.firstVisibleRow() == 200, QStringLiteral("一档滚轮向上应回到 200，实际 %1").arg(canvas.firstVisibleRow()));
            // 连续三档：9 行，不是三页。
            for (int step = 0; step < 3; ++step)
            {
                SendWheel(canvas, -120, Qt::NoModifier);
            }
            settle();
            CHECK_NOTE(canvas.firstVisibleRow() == 209, QStringLiteral("连续三档应滚 9 行（200->209），实际 %1").arg(canvas.firstVisibleRow()));

            // 复位：别影响后面的测试（过滤器本身保持已安装，关闭启用即可）。
            ks::ui::SetGlobalSmoothScrollingEnabled(false);
        }

        // 字号缩放：级别夹取与信号；cellRect 宽度随字号变化；缩小后首行夹取（末尾不出空白带）；
        // Ctrl+滚轮（累计成一档、不滚动内容）；Ctrl+= / Ctrl++ / Ctrl+- / Ctrl+0；无数据时也能缩放。
        // 杀死：缩放不重建度量；字体变化分支不夹取首行（末尾空白带）；Ctrl+滚轮仍滚动；滚轮不累计；
        // 键盘缩放键缺失；Ctrl+0 不恢复；缩放级别不夹取。
        void TestZoom()
        {
            ApplyTheme(false);

            // 级别、信号、夹取、cellRect 宽度。
            {
                auto fixture = MakeStaticFixture(kBase, MakePattern(kSpaceBytes), false, QSize(1500, 420));
                HexCanvas& canvas = *fixture->canvas;
                QSignalSpy zoomSpy(&canvas, &HexCanvas::zoomLevelChanged);
                CHECK(HexCanvas::kMinZoomLevel == -4 && HexCanvas::kMaxZoomLevel == 12);
                const std::uint64_t address = kBase + 3ULL;
                const int widthBefore = canvas.cellRect(address, Pane::Hex).width();
                CHECK(canvas.zoomLevel() == 0);
                canvas.zoomBy(2);
                CHECK(canvas.zoomLevel() == 2);
                CHECK(zoomSpy.count() == 1 && zoomSpy.at(0).at(0).toInt() == 2);
                CHECK_NOTE(
                    canvas.cellRect(address, Pane::Hex).width() > widthBefore,
                    QStringLiteral("放大后单元格宽度应变大（%1 -> %2）").arg(widthBefore).arg(canvas.cellRect(address, Pane::Hex).width()));
                canvas.setZoomLevel(99);
                CHECK(canvas.zoomLevel() == 12);
                canvas.setZoomLevel(-99);
                CHECK(canvas.zoomLevel() == -4);
                CHECK(zoomSpy.count() == 3);
                canvas.setZoomLevel(-4);                // 同级别：不发信号
                CHECK(zoomSpy.count() == 3);
                canvas.zoomReset();
                CHECK(canvas.zoomLevel() == 0);
                CHECK(canvas.cellRect(address, Pane::Hex).width() == widthBefore);
                CHECK(zoomSpy.count() == 4);
            }

            // 缩小后首行夹取：先滚到末屏，缩小字号后可见行变多、最大首行变小，首行必须跟着夹取。
            {
                auto fixture = MakeStaticFixture(kBase, MakePattern(kSpaceBytes), false, QSize(1500, 420));
                HexCanvas& canvas = *fixture->canvas;
                const std::uint64_t rows = static_cast<std::uint64_t>(kSpaceBytes) / 16ULL;
                canvas.setFirstVisibleRow(0xFFFFFFULL);     // 夹取到最大首行
                const std::uint64_t visibleBefore = canvas.visibleRowCount();
                CHECK(canvas.firstVisibleRow() + visibleBefore == rows);        // 前置：确实在末屏
                // 缩放后可见范围变了必须通知（页请求规划与基线喂入器都订阅它）：字体变化分支漏调 notifyVisibleRange 会让它们沿用旧范围。
                QSignalSpy rangeSpy(&canvas, &HexCanvas::visibleRangeChanged);
                canvas.zoomBy(-4);
                CHECK_NOTE(rangeSpy.count() >= 1, QStringLiteral("缩小字号后应发 visibleRangeChanged，实际 %1 次").arg(rangeSpy.count()));
                CHECK_NOTE(canvas.visibleRowCount() > visibleBefore, QStringLiteral("缩小字号后应多露出行（%1 -> %2）").arg(visibleBefore).arg(canvas.visibleRowCount()));
                CHECK_NOTE(
                    canvas.firstVisibleRow() + canvas.visibleRowCount() <= rows,
                    QStringLiteral("缩小字号后首行 %1 + 可见 %2 超过总行数 %3：末尾出现空白带")
                        .arg(canvas.firstVisibleRow()).arg(canvas.visibleRowCount()).arg(rows));
                CHECK(!canvas.cellRect(kBase + static_cast<std::uint64_t>(kSpaceBytes) - 1ULL, Pane::Hex).isNull());   // 末字节仍可见
            }

            // Ctrl+滚轮：累计 120 成一档（三次 40 才缩放一次）、向上放大向下缩小、不滚动内容；
            // 不带 Ctrl 的滚轮仍是滚动。
            {
                auto fixture = MakeStaticFixture(kBase, MakePattern(kSpaceBytes), false, QSize(1500, 420));
                HexCanvas& canvas = *fixture->canvas;
                canvas.setFirstVisibleRow(100);
                const int widthBefore = canvas.cellRect(kBase + 100ULL * 16ULL, Pane::Hex).width();
                CHECK(widthBefore > 0);
                for (int step = 0; step < 2; ++step)
                {
                    SendWheel(canvas, 40, Qt::ControlModifier);
                    CHECK_NOTE(canvas.zoomLevel() == 0, QStringLiteral("累计不足 120 不应缩放（第 %1 次）").arg(step + 1));
                }
                SendWheel(canvas, 40, Qt::ControlModifier);                     // 第三次凑够 120：放大一档
                CHECK(canvas.zoomLevel() == 1);
                CHECK(canvas.firstVisibleRow() == 100);                          // 没有滚动
                SendWheel(canvas, -120, Qt::ControlModifier);                   // 向下：缩小一档
                CHECK(canvas.zoomLevel() == 0);
                CHECK(canvas.firstVisibleRow() == 100);
                SendWheel(canvas, 240, Qt::ControlModifier);                    // 一个事件两档
                CHECK(canvas.zoomLevel() == 2);
                CHECK(canvas.firstVisibleRow() == 100);
                canvas.zoomReset();
                SendWheel(canvas, -120, Qt::NoModifier);                        // 不带 Ctrl：滚动 3 行
                CHECK(canvas.zoomLevel() == 0);
                CHECK(canvas.firstVisibleRow() == 103);
                CHECK(canvas.cellRect(kBase + 103ULL * 16ULL, Pane::Hex).width() == widthBefore);
            }

            // 滚轮零头累计：90 + 90 = 180 -> 缩放一档并留下 60；再来 60 凑成 120 -> 又一档。
            // 前面的序列余量恒为 0，抓不到"凑够一档后把累加器清零（丢掉零头）"的缺陷。
            {
                auto fixture = MakeStaticFixture(kBase, MakePattern(kSpaceBytes), false, QSize(1500, 420));
                HexCanvas& canvas = *fixture->canvas;
                SendWheel(canvas, 90, Qt::ControlModifier);
                CHECK(canvas.zoomLevel() == 0);
                SendWheel(canvas, 90, Qt::ControlModifier);
                CHECK_NOTE(canvas.zoomLevel() == 1, QStringLiteral("累计 180 应缩放一档，实际 %1").arg(canvas.zoomLevel()));
                SendWheel(canvas, 60, Qt::ControlModifier);
                CHECK_NOTE(canvas.zoomLevel() == 2, QStringLiteral("留下的零头 60 再加 60 应凑成第二档，实际 %1").arg(canvas.zoomLevel()));
            }

            // 键盘：Ctrl+= / Ctrl++ 放大，Ctrl+- 缩小，Ctrl+0 恢复默认；插入点与选区不受影响。
            {
                auto fixture = MakeStaticFixture(kBase, MakePattern(kSpaceBytes), false, QSize(1500, 420));
                HexCanvas& canvas = *fixture->canvas;
                const std::uint64_t address = kBase + 3ULL;
                const int widthBefore = canvas.cellRect(address, Pane::Hex).width();
                canvas.setCaretAddress(kBase + 5ULL);
                Key(canvas, Qt::Key_Equal, Qt::ControlModifier);
                CHECK(canvas.zoomLevel() == 1);
                Key(canvas, Qt::Key_Plus, Qt::ControlModifier);
                CHECK(canvas.zoomLevel() == 2);
                Key(canvas, Qt::Key_Minus, Qt::ControlModifier);
                CHECK(canvas.zoomLevel() == 1);
                Key(canvas, Qt::Key_Equal, Qt::ControlModifier);
                Key(canvas, Qt::Key_Equal, Qt::ControlModifier);
                CHECK(canvas.zoomLevel() == 3);
                Key(canvas, Qt::Key_0, Qt::ControlModifier);
                CHECK(canvas.zoomLevel() == 0);
                CHECK(canvas.cellRect(address, Pane::Hex).width() == widthBefore);   // 字体真的恢复了
                CHECK(canvas.caretAddress() == kBase + 5ULL);
            }

            // 没有地址空间时缩放键也有效（键盘缩放放在"无数据直接交给基类"之前）。
            {
                HexCanvas empty;
                empty.resize(600, 300);
                empty.show();
                Key(empty, Qt::Key_Equal, Qt::ControlModifier);
                CHECK(empty.zoomLevel() == 1);
                Key(empty, Qt::Key_0, Qt::ControlModifier);
                CHECK(empty.zoomLevel() == 0);
            }
        }
    }

    // 本文件全部测试的入口（由 memwb_ui_tests.cpp 的 main 调用）。
    void RunRowFitTests()
    {
        TestPureFunctions();
        TestLayoutIdentity();
        TestViewportDrivesRowWidth();
        TestAnchor();
        TestNoRereadOnRowWidthChange();
        TestManualBeatsAuto();
        TestLinkedTriggers();
        TestVerticalMinimum();
        TestZoom();
        TestWheelUnderGlobalSmoothScroll();
    }
}
