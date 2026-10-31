// memwb_ui_tests.HexView.Find.cpp
// 作用：HexView 查找条的离屏验证（经真实的 QLineEdit/按钮/快捷键与后台线程）——
//   四种模式（十六进制连写/前缀/逗号/通配、UTF-8、UTF-16LE、ANSI）、起点规则、
//   回绕明示（"已从头继续" / "已从末尾继续"）、未找到、无效模式的位置、无数据；
//   可见范围高亮（只算可见范围、跨边界命中、重叠命中、命中层号与悬停提示、主题切换后重新着色、
//   编辑/静默改字节/换数据后清除）；
//   后台搜索（不阻塞 UI、取消、陈旧结果丢弃、被新搜索取代、销毁控件时安全）。
// 纯逻辑与差分测试在 memwb_ui_tests.HexView.FindLogic.cpp。

#include "memwb_ui_hexview.h"

#include <QApplication>
#include <QElapsedTimer>
#include <QLineEdit>

#include <iostream>

namespace memwb_test
{
    namespace
    {
        using ks::ui::HexCanvas;
        using ks::ui::HexFindBar;
        using ks::ui::HexView;
        using Pane = HexCanvas::ActivePane;
        using Mode = HexFindBar::Mode;

        // kBase：测试数据的起始地址；数据 8192 字节，覆盖 0x1000..0x2FFF。
        constexpr std::uint64_t kBase = 0x1000;

        // Put：把字节写进数据的指定偏移。
        void Put(QByteArray& data, int offset, const QByteArray& bytes)
        {
            for (int index = 0; index < bytes.size(); ++index)
            {
                data[offset + index] = bytes.at(index);
            }
        }

        // MakeFindData：填充 0xEE，在已知偏移放置各种模式（偏移表见各用例）。
        //   0x010 / 0x500  4D 5A 90 00          0x600  4D 11 90 A0（通配的诱饵）
        //   0x200 Hello    0x300 hello    0x400 HELLO
        //   0x700  AA AA AA AA AA（5 个 AA：重叠命中）
        //   0x800  48 00 69 00（UTF-16 "Hi"）    0x900  Hi（ASCII）
        //   0xA00  E5 AD 97（UTF-8 "字"）        0xB00  57 5B（UTF-16 "字"）
        //   0x1EE  5A 51 5A 51（跨 16 字节行边界：地址 0x11EE..0x11F1）
        QByteArray MakeFindData()
        {
            QByteArray data(8192, static_cast<char>(0xEE));
            Put(data, 0x010, QByteArray::fromHex("4D5A9000"));
            Put(data, 0x500, QByteArray::fromHex("4D5A9000"));
            Put(data, 0x600, QByteArray::fromHex("4D1190A0"));
            Put(data, 0x200, QByteArray("Hello"));
            Put(data, 0x300, QByteArray("hello"));
            Put(data, 0x400, QByteArray("HELLO"));
            Put(data, 0x700, QByteArray::fromHex("AAAAAAAAAA"));
            Put(data, 0x800, QByteArray::fromHex("48006900"));
            Put(data, 0x900, QByteArray("Hi"));
            Put(data, 0xA00, QByteArray::fromHex("E5AD97"));
            Put(data, 0xB00, QByteArray::fromHex("575B"));
            Put(data, 0x1EE, QByteArray::fromHex("5A515A51"));
            return data;
        }

        // FindRun：一次查找的观察结果。
        struct FindRun
        {
            bool started = false;           // 搜索是否启动
            bool completed = false;         // 是否在时限内完成
            bool found = false;             // 是否命中
            std::uint64_t address = 0;      // 命中起点
            std::uint64_t length = 0;       // 命中长度
            bool wrapped = false;           // 是否回绕
        };

        // RunFind：触发一次下一个/上一个并等到结果。
        FindRun RunFind(HexView& view, bool forward)
        {
            HexFindBar& bar = *view.findBar();
            QSignalSpy matchSpy(&bar, &HexFindBar::matchFound);
            QSignalSpy doneSpy(&bar, &HexFindBar::searchCompleted);
            FindRun run;
            run.started = forward ? bar.findNext() : bar.findPrevious();
            if (!run.started)
            {
                return run;
            }
            run.completed = PumpUntil([&]() { return doneSpy.count() >= 1; }, 8000);
            if (run.completed)
            {
                run.found = doneSpy.at(0).at(0).toBool();
            }
            if (matchSpy.count() >= 1)
            {
                run.address = matchSpy.at(0).at(0).toULongLong();
                run.length = matchSpy.at(0).at(1).toULongLong();
                run.wrapped = matchSpy.at(0).at(2).toBool();
            }
            return run;
        }

        // Configure：设置模式、输入与大小写。
        void Configure(HexView& view, Mode mode, const QString& text, bool caseSensitive = false)
        {
            view.findBar()->setMode(mode);
            view.findBar()->setCaseSensitive(caseSensitive);
            view.findBar()->setPatternText(text);
        }

        // SelectedIs：画布选区是否正好是 [first, last]，插入点在 first。
        bool SelectedIs(HexView& view, std::uint64_t first, std::uint64_t last)
        {
            const std::optional<HexCanvas::AddressRange> range = view.canvas()->selectedRange();
            return range.has_value() && range->first == first && range->last == last && view.caretAddress() == first;
        }

        // 十六进制模式：连写、前缀、逗号、通配；上一个/下一个、回绕明示、起点规则。
        void TestHexMode()
        {
            ApplyTheme(false);
            const QByteArray data = MakeFindData();
            auto view = MakeHexView(kBase, data, false, QSize(1000, 420));
            HexFindBar& bar = *view->findBar();
            bar.open();
            CHECK(bar.isVisible());
            CHECK(bar.lineEdit()->hasFocus() || !view->isActiveWindow());

            // 基本：从插入点（0x1000）向后找，命中 0x1010，选中命中范围，结果文字带起始地址。
            Configure(*view, Mode::Hex, QStringLiteral("4D 5A 90 00"));
            FindRun run = RunFind(*view, true);
            CHECK(run.started && run.completed && run.found);
            CHECK(run.address == 0x1010 && run.length == 4 && !run.wrapped);
            CHECK(SelectedIs(*view, 0x1010, 0x1013));
            CHECK(bar.resultText().startsWith(QStringLiteral("已找到 0x00001010")));
            CHECK(bar.resultKind() == ks::ui::HexViewMessageLabel::Kind::Info);
            CHECK(!bar.isSearching());

            // 下一个：选区就是上次命中 -> 从命中起点 + 1 开始，到 0x1500；命中被滚动到可见。
            run = RunFind(*view, true);
            CHECK(run.found && run.address == 0x1500 && !run.wrapped);
            CHECK(SelectedIs(*view, 0x1500, 0x1503));
            CHECK(!view->canvas()->cellRect(0x1500, Pane::Hex).isNull());

            // 再下一个：到尾回绕，明示"已从头继续"，命中 0x1010。
            run = RunFind(*view, true);
            CHECK(run.found && run.address == 0x1010 && run.wrapped);
            CHECK(bar.resultText().contains(QStringLiteral("已从头继续")));
            CHECK(bar.resultText().contains(QStringLiteral("0x00001010")));

            // 上一个：从 0x1010 往前，回绕到末尾的 0x1500，明示"已从末尾继续"；再上一个回到 0x1010 且不回绕。
            run = RunFind(*view, false);
            CHECK(run.found && run.address == 0x1500 && run.wrapped);
            CHECK(bar.resultText().contains(QStringLiteral("已从末尾继续")));
            run = RunFind(*view, false);
            CHECK(run.found && run.address == 0x1010 && !run.wrapped);
            CHECK(!bar.resultText().contains(QStringLiteral("继续")));

            // 起点规则：用户点到别处后，从新选区起点（含）开始，而不是从上次命中 + 1。
            ClickAddress(*view->canvas(), 0x1000);
            run = RunFind(*view, true);
            CHECK(run.found && run.address == 0x1010 && !run.wrapped);
            ClickAddress(*view->canvas(), 0x1500);
            run = RunFind(*view, true);
            CHECK(run.found && run.address == 0x1500 && !run.wrapped);
            ClickAddress(*view->canvas(), 0x1501);
            run = RunFind(*view, true);
            CHECK(run.found && run.address == 0x1010 && run.wrapped);

            // 改了模式再回车：选区仍是旧模式的命中，新模式要从选区起点（含）重新找，不能因为"选区就是上次命中"
            // 而从起点 + 1 开始、跳过同一起点上的新命中。
            ClickAddress(*view->canvas(), 0x1000);
            Configure(*view, Mode::Hex, QStringLiteral("4D 5A"));
            run = RunFind(*view, true);
            CHECK(run.found && run.address == 0x1010 && run.length == 2);
            Configure(*view, Mode::Hex, QStringLiteral("4D 5A 90 00"));
            run = RunFind(*view, true);
            CHECK(run.found && run.address == 0x1010 && run.length == 4 && !run.wrapped);
            CHECK(SelectedIs(*view, 0x1010, 0x1013));

            // 写法：连写、0x 前缀、逗号分隔，都命中同一个地方。
            for (const QString& text : { QStringLiteral("4D5A9000"), QStringLiteral("0x4D 0x5A 0x90 0x00"),
                                         QStringLiteral("4d,5a,90,00"), QStringLiteral("  4D5A  9000  ") })
            {
                ClickAddress(*view->canvas(), 0x1000);
                Configure(*view, Mode::Hex, text);
                run = RunFind(*view, true);
                CHECK_NOTE(run.found && run.address == 0x1010 && run.length == 4, text);
            }

            // 通配：?? 整字节、?0 低半字节；依次命中 0x1010、0x1500、0x1600（诱饵），与朴素查找一致，随后回绕。
            ClickAddress(*view->canvas(), 0x1000);
            Configure(*view, Mode::Hex, QStringLiteral("4D ?? 90 ?0"));
            const std::vector<std::uint64_t> expected = NaiveMatches(
                data, kBase, QByteArray::fromHex("4D009000"), QByteArray::fromHex("FF00FF0F"));
            CHECK(expected == (std::vector<std::uint64_t>{ 0x1010, 0x1500, 0x1600 }));
            for (std::size_t index = 0; index < expected.size(); ++index)
            {
                run = RunFind(*view, true);
                CHECK_NOTE(run.found && run.address == expected[index] && !run.wrapped, QString::number(index));
            }
            run = RunFind(*view, true);
            CHECK(run.found && run.address == expected[0] && run.wrapped);

            // 半字节通配 "?? 5A"：与朴素查找全部命中一致（逐个走完一圈）。
            ClickAddress(*view->canvas(), 0x1000);
            Configure(*view, Mode::Hex, QStringLiteral("?? 5A"));
            const std::vector<std::uint64_t> wildcardExpected = NaiveMatches(
                data, kBase, QByteArray::fromHex("005A"), QByteArray::fromHex("00FF"));
            CHECK(!wildcardExpected.empty());
            std::vector<std::uint64_t> seen;
            for (std::size_t index = 0; index < wildcardExpected.size(); ++index)
            {
                run = RunFind(*view, true);
                seen.push_back(run.address);
            }
            CHECK(seen == wildcardExpected);

            // 重叠命中：5 个 AA 里找 "AA AA AA"，起点依次是 0x1700、0x1701、0x1702。
            ClickAddress(*view->canvas(), 0x1000);
            Configure(*view, Mode::Hex, QStringLiteral("AA AA AA"));
            for (const std::uint64_t expectedAddress : { 0x1700ULL, 0x1701ULL, 0x1702ULL })
            {
                run = RunFind(*view, true);
                CHECK(run.found && run.address == expectedAddress && !run.wrapped);
            }
            run = RunFind(*view, true);
            CHECK(run.found && run.address == 0x1700 && run.wrapped);
        }

        // 文本模式：UTF-8 大小写、UTF-16LE、非 ASCII；大小写开关只在文本模式可用。
        void TestTextModes()
        {
            ApplyTheme(false);
            const QByteArray data = MakeFindData();
            auto view = MakeHexView(kBase, data, false, QSize(1000, 420));
            HexFindBar& bar = *view->findBar();
            bar.open();

            // 大小写开关：十六进制模式禁用，文本模式可用；占位提示随模式变化。
            CHECK(!bar.caseButton()->isEnabled());
            const QString hexPlaceholder = bar.lineEdit()->placeholderText();
            bar.setMode(Mode::TextUtf8);
            CHECK(bar.caseButton()->isEnabled());
            CHECK(bar.lineEdit()->placeholderText() != hexPlaceholder);
            bar.setMode(Mode::TextUtf16Le);
            CHECK(bar.lineEdit()->placeholderText() != hexPlaceholder);
            bar.setMode(Mode::Hex);
            CHECK(!bar.caseButton()->isEnabled());

            // 默认忽略大小写：hello 依次命中 Hello / hello / HELLO，再回绕。
            Configure(*view, Mode::TextUtf8, QStringLiteral("hello"));
            FindRun run;
            for (const std::uint64_t expectedAddress : { 0x1200ULL, 0x1300ULL, 0x1400ULL })
            {
                run = RunFind(*view, true);
                CHECK(run.found && run.address == expectedAddress && run.length == 5 && !run.wrapped);
            }
            run = RunFind(*view, true);
            CHECK(run.found && run.address == 0x1200 && run.wrapped);

            // 区分大小写：只有小写的 hello（唯一命中，下一个回绕回自己）。
            ClickAddress(*view->canvas(), 0x1000);
            Configure(*view, Mode::TextUtf8, QStringLiteral("hello"), true);
            run = RunFind(*view, true);
            CHECK(run.found && run.address == 0x1300 && !run.wrapped);
            run = RunFind(*view, true);
            CHECK(run.found && run.address == 0x1300 && run.wrapped);

            // UTF-16LE："Hi" 命中 48 00 69 00（长度 4），不会命中 ASCII 的 Hi；UTF-8 模式反之。
            ClickAddress(*view->canvas(), 0x1000);
            Configure(*view, Mode::TextUtf16Le, QStringLiteral("Hi"), true);
            run = RunFind(*view, true);
            CHECK(run.found && run.address == 0x1800 && run.length == 4);
            ClickAddress(*view->canvas(), 0x1000);
            Configure(*view, Mode::TextUtf8, QStringLiteral("Hi"), true);
            run = RunFind(*view, true);
            CHECK(run.found && run.address == 0x1900 && run.length == 2);

            // 非 ASCII：UTF-8 的 "字" 是 3 字节，UTF-16LE 是 2 字节。
            ClickAddress(*view->canvas(), 0x1000);
            Configure(*view, Mode::TextUtf8, QStringLiteral("字"));
            run = RunFind(*view, true);
            CHECK(run.found && run.address == 0x1A00 && run.length == 3);
            ClickAddress(*view->canvas(), 0x1000);
            Configure(*view, Mode::TextUtf16Le, QStringLiteral("字"));
            run = RunFind(*view, true);
            CHECK(run.found && run.address == 0x1B00 && run.length == 2);
        }

        // 未找到、无效模式（含位置）、没有数据：结果文字明确，不启动搜索，不动选区。
        void TestNotFoundAndInvalid()
        {
            ApplyTheme(false);
            auto view = MakeHexView(kBase, MakeFindData(), false, QSize(1000, 420));
            HexFindBar& bar = *view->findBar();
            bar.open();
            ClickAddress(*view->canvas(), 0x1100);
            const std::optional<HexCanvas::AddressRange> selection = view->canvas()->selectedRange();

            // 未找到：整圈扫过没有命中；高亮清空，选区不动。
            QSignalSpy matchSpy(&bar, &HexFindBar::matchFound);
            Configure(*view, Mode::Hex, QStringLiteral("DE AD BE EF"));
            FindRun run = RunFind(*view, true);
            CHECK(run.started && run.completed && !run.found);
            CHECK(bar.resultText() == QStringLiteral("未找到"));
            CHECK(bar.resultKind() == ks::ui::HexViewMessageLabel::Kind::Warning);
            CHECK(matchSpy.isEmpty());
            CHECK(!bar.highlightActive() && bar.highlightRanges().empty());
            CHECK(view->canvas()->selectedRange() == selection);

            // 无效模式：不启动搜索，文字是"无效模式：第 N 个字符处有误"（N 是 1 起的字符序号）。
            struct Case
            {
                QString text;       // 输入
                QString expected;   // 期望的结果文字
            };
            const std::vector<Case> cases = {
                { QStringLiteral("4D5"), QStringLiteral("无效模式：第 3 个字符处有误") },
                { QStringLiteral("4G"), QStringLiteral("无效模式：第 2 个字符处有误") },
                { QStringLiteral("中"), QStringLiteral("无效模式：第 1 个字符处有误") },
                { QStringLiteral("0x"), QStringLiteral("无效模式：第 1 个字符处有误") },
                { QStringLiteral("4D 5Z"), QStringLiteral("无效模式：第 5 个字符处有误") },
                { QString(), QStringLiteral("无效模式：输入为空") },
                { QStringLiteral("  ,, "), QStringLiteral("无效模式：输入为空") },
            };
            for (const Case& entry : cases)
            {
                Configure(*view, Mode::Hex, entry.text);
                const bool started = bar.findNext();
                CHECK_NOTE(!started, entry.text);
                CHECK_NOTE(bar.resultText() == entry.expected, entry.text + QStringLiteral(" -> ") + bar.resultText());
                CHECK(bar.resultKind() == ks::ui::HexViewMessageLabel::Kind::Error);
                CHECK(!bar.isSearching());
            }
            CHECK(matchSpy.isEmpty());
            CHECK(view->canvas()->selectedRange() == selection);

            // 文本模式空输入同样是无效；不会把"空文本"当成匹配一切。
            Configure(*view, Mode::TextUtf8, QString());
            CHECK(!bar.findNext());
            CHECK(bar.resultText() == QStringLiteral("无效模式：输入为空"));

            // 没有数据：明确提示，不启动。
            view->clearBuffer();
            Configure(*view, Mode::Hex, QStringLiteral("4D"));
            CHECK(!bar.findNext());
            CHECK(bar.resultText() == QStringLiteral("没有可查找的数据"));
            CHECK(bar.resultKind() == ks::ui::HexViewMessageLabel::Kind::Warning);
            CHECK(!bar.isSearching());
        }

        // 工具栏按钮、回车、关闭按钮、焦点。
        void TestFindBarInteraction()
        {
            ApplyTheme(false);
            auto view = MakeHexView(kBase, MakeFindData(), false, QSize(1000, 420));
            HexFindBar& bar = *view->findBar();

            // 点工具栏查找按钮：条打开，焦点进输入框。
            QTest::mouseClick(view->findButton(), Qt::LeftButton);
            Flush();
            CHECK(bar.isVisible());

            // 悬停提示：按钮、四个模式段都有。
            for (ks::ui::HexViewGlyphButton* button : { bar.caseButton(), bar.previousButton(), bar.nextButton(), bar.closeButton() })
            {
                CHECK(!button->toolTip().isEmpty());
            }
            for (int index = 0; index < 4; ++index)
            {
                CHECK(!bar.modeSegment()->segmentToolTip(index).isEmpty());
            }
            CHECK(bar.modeSegment()->count() == 4);

            // 回车 = 下一个；下一个按钮 / 上一个按钮。
            Configure(*view, Mode::Hex, QStringLiteral("4D 5A 90 00"));
            QSignalSpy matchSpy(&bar, &HexFindBar::matchFound);
            QTest::keyClick(bar.lineEdit(), Qt::Key_Return);
            CHECK(PumpUntil([&]() { return matchSpy.count() == 1; }, 5000));
            CHECK(matchSpy.at(0).at(0).toULongLong() == 0x1010);
            QTest::mouseClick(bar.nextButton(), Qt::LeftButton);
            CHECK(PumpUntil([&]() { return matchSpy.count() == 2; }, 5000));
            CHECK(matchSpy.at(1).at(0).toULongLong() == 0x1500);
            QTest::mouseClick(bar.previousButton(), Qt::LeftButton);
            CHECK(PumpUntil([&]() { return matchSpy.count() == 3; }, 5000));
            CHECK(matchSpy.at(2).at(0).toULongLong() == 0x1010);

            // 点模式分段按钮真的切换模式。
            const QRect utf8 = bar.modeSegment()->segmentRect(1);
            QTest::mouseClick(bar.modeSegment(), Qt::LeftButton, Qt::NoModifier, utf8.center());
            CHECK(bar.mode() == Mode::TextUtf8);
            QTest::mouseClick(bar.modeSegment(), Qt::LeftButton, Qt::NoModifier, bar.modeSegment()->segmentRect(3).center());
            CHECK(bar.mode() == Mode::TextAnsi);
            CHECK(bar.caseButton()->isEnabled());
            CHECK(bar.lineEdit()->placeholderText().contains(QString::number(ks::ui::hexfind::SystemAnsiCodePage())));
            QTest::mouseClick(bar.modeSegment(), Qt::LeftButton, Qt::NoModifier, bar.modeSegment()->segmentRect(0).center());
            CHECK(bar.mode() == Mode::Hex);

            // 关闭按钮：条隐藏，高亮与结果清除，在途搜索作废，焦点回到画布。
            CHECK(bar.highlightActive());
            QTest::mouseClick(bar.closeButton(), Qt::LeftButton);
            Flush();
            CHECK(!bar.isVisible());
            CHECK(!bar.highlightActive() && bar.highlightRanges().empty());
            CHECK(bar.resultText().isEmpty());
            CHECK(!CellOf(*view, 0x1010).highlighted);

            // 再次打开：输入框保留上次的文字并全选。
            view->openFind();
            Flush();
            CHECK(bar.isVisible());
            CHECK(bar.patternText() == QStringLiteral("4D 5A 90 00"));
            CHECK(bar.lineEdit()->selectedText() == bar.patternText());
        }

        // 可见范围高亮：层号、悬停提示、只算可见范围、跟随滚动、跨边界命中、重叠命中、主题重新着色。
        void TestHighlights()
        {
            ApplyTheme(false);
            const QByteArray data = MakeFindData();
            auto view = MakeHexView(kBase, data, false, QSize(1000, 420));
            HexFindBar& bar = *view->findBar();
            HexCanvas& canvas = *view->canvas();
            bar.open();

            // 命中 0x1010：当前视口里只有这一处命中；高亮层是约定的层号，悬停提示是"查找命中"。
            Configure(*view, Mode::Hex, QStringLiteral("4D 5A 90 00"));
            FindRun run = RunFind(*view, true);
            CHECK(run.found && run.address == 0x1010);
            CHECK(bar.highlightRanges().size() == 1);
            if (bar.highlightRanges().size() == 1)
            {
                CHECK(bar.highlightRanges()[0].first == 0x1010 && bar.highlightRanges()[0].last == 0x1013);
            }
            for (std::uint64_t address = 0x1010; address <= 0x1013; ++address)
            {
                const HexCanvas::CellState cell = CellOf(*view, address);
                CHECK(cell.highlighted && cell.highlightLayerId == HexView::kFindHighlightLayer);
            }
            CHECK(!CellOf(*view, 0x100F).highlighted && !CellOf(*view, 0x1014).highlighted);
            CHECK(canvas.cellToolTip(0x1010).contains(QStringLiteral("查找命中")));

            // 滚动跟随：滚到 0x1500 附近，高亮换成那里的命中（只算可见范围，旧命中不在视口里就不再列出）。
            canvas.scrollToAddress(0x1500, HexCanvas::ScrollAlign::Top);
            Flush();
            CHECK(bar.highlightRanges().size() == 1);
            if (bar.highlightRanges().size() == 1)
            {
                CHECK(bar.highlightRanges()[0].first == 0x1500 && bar.highlightRanges()[0].last == 0x1503);
            }
            CHECK(CellOf(*view, 0x1500).highlighted);
            CHECK(!CellOf(*view, 0x1010).highlighted);

            // 视口里没有命中：列表为空，状态仍是"有命中"（滚回来就又有）。
            canvas.scrollToAddress(0x2000, HexCanvas::ScrollAlign::Top);
            Flush();
            CHECK(bar.highlightRanges().empty());
            CHECK(bar.highlightActive());
            canvas.scrollToAddress(0x1000, HexCanvas::ScrollAlign::Top);
            Flush();
            CHECK(bar.highlightRanges().size() == 1);

            // 重叠命中：5 个 AA 里的 "AA AA" 有 4 个重叠命中，逐个列出（画布高亮层再把它们并成一段）。
            Configure(*view, Mode::Hex, QStringLiteral("AA AA"));
            ClickAddress(canvas, 0x1000);
            run = RunFind(*view, true);
            CHECK(run.found && run.address == 0x1700);
            CHECK(bar.highlightRanges().size() == 4);
            for (std::uint64_t address = 0x1700; address <= 0x1704; ++address)
            {
                CHECK(CellOf(*view, address).highlighted);
            }
            CHECK(!CellOf(*view, 0x1705).highlighted && !CellOf(*view, 0x16FF).highlighted);

            // 跨行边界命中：5A 51 5A 51 位于 0x11EE..0x11F1，首个可见行从 0x11F0 开始时，起点在视口之前的命中仍然高亮。
            Configure(*view, Mode::Hex, QStringLiteral("5A 51 5A 51"));
            ClickAddress(canvas, 0x1000);
            run = RunFind(*view, true);
            CHECK(run.found && run.address == 0x11EE);
            canvas.setFirstVisibleRow(0x1F0 / 16);
            Flush();
            bool straddles = false;
            for (const HexCanvas::AddressRange& range : bar.highlightRanges())
            {
                straddles = straddles || (range.first == 0x11EE && range.last == 0x11F1);
            }
            CHECK(straddles);
            CHECK(CellOf(*view, 0x11F0).highlighted && CellOf(*view, 0x11F1).highlighted);

            // 主题切换后高亮色重新取：像素底色等于当前主题下"表面色与黄色强调色按层权重混合"的结果。
            run = RunFind(*view, true);
            Flush();
            CHECK(run.found);
            for (const bool dark : { false, true, false })
            {
                ApplyTheme(dark);
                Flush();

                // 选区会盖在高亮之上，所以先把选区折叠到别处，再把命中滚到视口中央，取命中第二个字节的单元格底色。
                canvas.setCaretAddress(0x1000, false, false);
                canvas.scrollToAddress(run.address, HexCanvas::ScrollAlign::Center);
                Flush();
                const QRect hitRect = canvas.cellRect(run.address + 1, Pane::Hex);
                CHECK(!hitRect.isNull());
                const QImage image = GrabImage(canvas);
                const QColor actual(image.pixel(hitRect.left() + 1, hitRect.top() + 1));
                const QColor expected = KswordTheme::BlendColors(
                    KswordTheme::SurfaceColor(), KswordTheme::AccentColor(KswordTheme::AccentRole::Yellow), 150);
                CHECK_NOTE(ColorsClose(actual, expected, 8),
                    QStringLiteral("dark=%1 actual=%2 expected=%3").arg(dark).arg(actual.name()).arg(expected.name()));
            }
            ApplyTheme(false);
        }

        // 缓冲变化清除高亮：键盘编辑、填充、静默改字节、换数据。
        void TestHighlightsClearedOnChange()
        {
            ApplyTheme(false);
            const QByteArray data = MakeFindData();
            auto view = MakeHexView(kBase, data, true, QSize(1000, 420));
            HexFindBar& bar = *view->findBar();
            HexCanvas& canvas = *view->canvas();
            bar.open();
            Configure(*view, Mode::Hex, QStringLiteral("4D 5A 90 00"));

            const auto startActive = [&]() {
                ClickAddress(canvas, 0x1000);
                const FindRun run = RunFind(*view, true);
                return run.found && bar.highlightActive() && !bar.highlightRanges().empty() && CellOf(*view, 0x1010).highlighted;
            };

            // 键盘编辑任意字节（不在命中里）：高亮、命中状态、结果提示都清除。
            CHECK(startActive());
            ClickAddress(canvas, 0x1100);
            canvas.setFocus();
            Type(canvas, QStringLiteral("5B"));
            Flush();
            CHECK(!bar.highlightActive() && bar.highlightRanges().empty());
            CHECK(!CellOf(*view, 0x1010).highlighted);
            CHECK(bar.resultText() == QStringLiteral("数据已变化，请重新查找"));

            // 填充命中范围本身。
            CHECK(startActive());
            ClickAddress(canvas, 0x1010);
            ClickAddress(canvas, 0x1013, Pane::Hex, Qt::ShiftModifier);
            canvas.fillSelection(0x00);
            Flush();
            CHECK(!bar.highlightActive() && !CellOf(*view, 0x1010).highlighted);
            view->setBuffer(kBase, data);

            // 静默改字节也清除（缓冲内容变了）。
            CHECK(startActive());
            CHECK(view->setByteQuiet(0x1100, 0x44));
            Flush();
            CHECK(!bar.highlightActive() && bar.highlightRanges().empty() && !CellOf(*view, 0x1010).highlighted);

            // 换数据。
            view->setBuffer(kBase, data);
            Configure(*view, Mode::Hex, QStringLiteral("4D 5A 90 00"));
            CHECK(startActive());
            view->setBuffer(kBase, data);
            Flush();
            CHECK(!bar.highlightActive() && bar.highlightRanges().empty() && !CellOf(*view, 0x1010).highlighted);
            CHECK(!view->canvas()->overlay()->HasPendingPatches());

            // 编辑后重新查找：新缓冲上的命中正确（编辑把 0x1010 的 4D 改成 4E，只剩 0x1500）。
            ClickAddress(canvas, 0x1010);
            canvas.setFocus();
            Type(canvas, QStringLiteral("4E"));
            Flush();
            ClickAddress(canvas, 0x1000);
            const FindRun run = RunFind(*view, true);
            CHECK(run.found && run.address == 0x1500);
        }

        // 后台搜索：不阻塞 UI、取消、陈旧结果丢弃、被新搜索取代、销毁控件时安全。
        void TestBackgroundSearch()
        {
            ApplyTheme(false);

            // 两种时序各测一遍：
            //   settleFirst=false  第一次搜索还在途就被取代/作废——线程可能在引擎的取消检查点就停下（结果带 cancelled）；
            //   settleFirst=true   第一次搜索已经完整跑完、结果回调已入队但还没被处理——这时挡住陈旧结果的只剩"票据对不上"，
            //                      没有取消标志兜底，所以这一档才真正验证票据判断。
            for (const bool settleFirst : { false, true })
            {
                // 小数据：被新搜索取代——只有第二次的结果生效。
                {
                    auto view = MakeHexView(kBase, MakeFindData(), false, QSize(1000, 420));
                    HexFindBar& bar = *view->findBar();
                    bar.open();
                    QSignalSpy matchSpy(&bar, &HexFindBar::matchFound);
                    QSignalSpy doneSpy(&bar, &HexFindBar::searchCompleted);
                    Configure(*view, Mode::Hex, QStringLiteral("4D 5A 90 00"));
                    CHECK(bar.findNext());
                    if (settleFirst)
                    {
                        CHECK(bar.waitForIdle(5000));
                    }
                    Configure(*view, Mode::TextUtf8, QStringLiteral("Hello"), true);
                    CHECK(bar.findNext());
                    CHECK(PumpUntil([&]() { return doneSpy.count() >= 1; }, 5000));
                    PumpFor(150);
                    CHECK_NOTE(doneSpy.count() == 1, QStringLiteral("settleFirst=%1 count=%2").arg(settleFirst).arg(doneSpy.count()));
                    CHECK(matchSpy.count() == 1 && matchSpy.at(0).at(0).toULongLong() == 0x1200);
                }

                // 小数据：数据变化让搜索作废——结果队列里的回调票据对不上，被丢弃。
                {
                    auto view = MakeHexView(kBase, MakeFindData(), false, QSize(1000, 420));
                    HexFindBar& bar = *view->findBar();
                    bar.open();
                    QSignalSpy matchSpy(&bar, &HexFindBar::matchFound);
                    QSignalSpy doneSpy(&bar, &HexFindBar::searchCompleted);
                    Configure(*view, Mode::Hex, QStringLiteral("4D 5A 90 00"));
                    const std::optional<HexCanvas::AddressRange> selection = view->canvas()->selectedRange();
                    CHECK(bar.findNext());
                    if (settleFirst)
                    {
                        CHECK(bar.waitForIdle(5000));
                    }
                    CHECK(view->setByteQuiet(0x2FFF, 0x01));
                    CHECK(bar.waitForIdle(5000));
                    PumpFor(200);
                    CHECK_NOTE(matchSpy.isEmpty() && doneSpy.isEmpty(), QStringLiteral("settleFirst=%1").arg(settleFirst));
                    CHECK(view->canvas()->selectedRange() == selection);
                    CHECK(!bar.highlightActive());
                    CHECK(!bar.isSearching());
                    CHECK(bar.resultText() == QStringLiteral("数据已变化，请重新查找"));
                }
            }

            // 大数据（64 MiB 全零）+ 慢模式（63 个 00 再加 01）：搜索在后台线程，UI 线程不被阻塞。
            const int size = 64 * 1024 * 1024;
            auto big = std::make_unique<HexView>();
            big->resize(1000, 420);
            big->show();
            big->setBuffer(0, QByteArray(size, '\0'));
            HexFindBar& bar = *big->findBar();
            bar.open();
            QString slowPattern;
            for (int index = 0; index < 63; ++index)
            {
                slowPattern += QStringLiteral("00 ");
            }
            slowPattern += QStringLiteral("01");
            Configure(*big, Mode::Hex, slowPattern);
            QSignalSpy doneSpy(&bar, &HexFindBar::searchCompleted);

            QElapsedTimer timer;
            timer.start();
            CHECK(bar.findNext());
            const qint64 startMs = timer.elapsed();
            CHECK(bar.isSearching());
            CHECK(bar.resultText() == QStringLiteral("正在查找…"));
            QApplication::processEvents();
            const qint64 firstPumpMs = timer.elapsed();
            CHECK(PumpUntil([&]() { return doneSpy.count() == 1; }, 120000));
            const qint64 totalMs = timer.elapsed();
            CHECK(bar.resultText() == QStringLiteral("未找到"));
            std::cout << "hexview find (64 MiB, slow pattern): findNext() returned in " << startMs
                      << " ms, first event pump " << firstPumpMs << " ms, whole search " << totalMs << " ms" << std::endl;
            CHECK_NOTE(startMs < 100, QString::number(startMs));
            CHECK_NOTE(totalMs > startMs * 3, QStringLiteral("search should run in background: start=%1 total=%2").arg(startMs).arg(totalMs));

            // 取消：慢搜索中途数据变化——线程在一个分块内停下，没有任何结果被应用。
            doneSpy.clear();
            CHECK(bar.findNext());
            PumpFor(30);
            timer.restart();
            bar.dataChanged();
            const bool idle = bar.waitForIdle(15000);
            const qint64 cancelMs = timer.elapsed();
            CHECK(idle);
            PumpFor(150);
            std::cout << "hexview find: cancel latency " << cancelMs << " ms" << std::endl;
            // 取消必须真的让线程提前停下：延迟远小于整个搜索（忽略取消标志的实现会跑满整个搜索时长）。
            CHECK_NOTE(cancelMs < 2000 && cancelMs < totalMs / 4,
                QStringLiteral("cancel=%1 ms total=%2 ms").arg(cancelMs).arg(totalMs));
            CHECK(doneSpy.isEmpty());
            CHECK(!bar.isSearching());
            CHECK(bar.resultText() == QStringLiteral("数据已变化，请重新查找"));

            // 销毁安全一：慢搜索进行中直接销毁整个控件。
            CHECK(bar.findNext());
            PumpFor(30);
            timer.restart();
            big.reset();
            const qint64 destroyMs = timer.elapsed();
            std::cout << "hexview find: destroy while searching " << destroyMs << " ms" << std::endl;
            CHECK_NOTE(destroyMs < 3000, QString::number(destroyMs));
            PumpFor(200);

            // 销毁安全二：搜索已结束、结果回调还在队列里时销毁控件，队列里的回调被丢弃。
            {
                auto view = MakeHexView(kBase, MakeFindData(), false, QSize(1000, 420));
                view->findBar()->open();
                Configure(*view, Mode::Hex, QStringLiteral("4D 5A 90 00"));
                CHECK(view->findBar()->findNext());
                CHECK(view->findBar()->waitForIdle(5000));
                view.reset();
                PumpFor(200);
            }
        }
    }

    // 查找条验证入口。
    void RunHexViewFindTests()
    {
        TestHexMode();
        TestTextModes();
        TestNotFoundAndInvalid();
        TestFindBarInteraction();
        TestHighlights();
        TestHighlightsClearedOnChange();
        TestBackgroundSearch();
    }
}
