// Real HexCanvas component checks and a repeatable paint/scroll benchmark.
// No target-process IO, native app automation or clipboard access.
#include "HexCanvas.h"
#include <QApplication>
#include <QElapsedTimer>
#include <QScrollBar>
#include <QToolButton>
#include <QTest>
#include <QFontDatabase>
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#ifdef HEX_VIEW_FEATURES
#include "WorkbenchStatusBar.h"
void runHexOverviewUiTests();
#include <QCheckBox>
#include <QPlainTextEdit>
#endif

using ks::ui::HexCanvas;
int checks = 0;
void check(bool value, const char* text) {
    ++checks;
    if (!value) { std::fprintf(stderr, "FAIL: %s\n", text); std::exit(1); }
}
void drain() { for (int i = 0; i < 30; ++i) QApplication::processEvents(); }
void draw(HexCanvas& c) { c.viewport()->repaint(); drain(); }

#ifdef HEX_VIEW_FEATURES
class Diagnostics final : public ks::ui::IWorkbenchDiagnosticsHost {
public:
    QPlainTextEdit* editor = new QPlainTextEdit;
    QWidget* HostWidget() override { return editor; }
    void SetDiagnosticsText(const QString& text) override { editor->setPlainText(text); }
    void SetDiagnosticsDocument(const ks::ui::FieldDocument&) override {}
    QString DiagnosticsText() const override { return editor->toPlainText(); }
    void SetWrapEnabled(bool wrap) override { editor->setLineWrapMode(wrap ? QPlainTextEdit::WidgetWidth : QPlainTextEdit::NoWrap); }
};
class UnreadableProvider final : public ks::ui::IHexPageProvider {
public:
    HexCanvas* canvas = nullptr;
    std::uint64_t pages = 0;
    bool folding = false;
    std::vector<ks::ui::HexFetchRange> requests;
    void SetUnknownFoldingEnabled(bool enabled) override { folding = enabled; }
    void RequestPages(const std::vector<ks::ui::HexFetchRange>& ranges, std::uint64_t revision) override {
        for (const auto& range : ranges) {
            requests.push_back(range);
            pages += range.pageCount;
            canvas->deliverUnreadable(range, revision);
        }
    }
};
QToolButton* button(HexCanvas& c, const QString& text) {
    for (auto* b : c.findChildren<QToolButton*>()) if (b->text() == text) return b;
    return nullptr;
}
void foldScrollStability() {
    // Match the screenshot's old caret at the last address while a small real
    // fragment is visible between unknown endpoints. A presentation toggle
    // should keep that fragment in view, rather than jump to the remote caret.
    {
        HexCanvas small;
        small.resize(900,420);small.setFoldUnknownRegions(true);
        small.setAddressSpace(0,0x7FFFFFFFFFFF);
        constexpr std::uint64_t fragment=0x4325C530970;
        QByteArray values(4096,'\0'),valid(4096,'\0');
        const int offset=static_cast<int>(fragment%4096);
        std::fill(values.begin()+offset,values.begin()+offset+32,'A');
        std::fill(valid.begin()+offset,valid.begin()+offset+32,'\1');
        small.setCaretAddress(0x7FFFFFFFFFFF,false,false);
        small.deliverPage(fragment-offset,values,valid,small.sourceRevision());
        small.show();draw(small);
        check(small.cellStateAt(fragment).hasValue && !small.cellRect(fragment,HexCanvas::ActivePane::Hex).isNull(),
            "sparse fragment is visible beside a remote unknown caret");
        const auto selection=small.selectedRange();
        for(int i=0;i<3;++i) {
            small.setFoldUnknownRegions(false);draw(small);
            check(!small.cellRect(fragment,HexCanvas::ActivePane::Hex).isNull(),
                "unfolding anchors the visible read fragment rather than an unknown endpoint caret");
            small.setFoldUnknownRegions(true);draw(small);
            check(small.cellStateAt(fragment).hasValue && !small.cellRect(fragment,HexCanvas::ActivePane::Hex).isNull(),
                "refolding retains the visible sparse fragment");
            check(small.selectedRange()==selection,"folding changes no caret or selection");
        }
    }
    HexCanvas c;
    c.resize(900, 420);
    c.setFoldUnknownRegions(true);
    constexpr std::uint64_t body = 0x1000000;
    c.setAddressSpace(0, body + 0x7FFF);
    const auto rev = c.sourceRevision();
    c.deliverPage(body - 0x100000, QByteArray(4096, '\x31'), QByteArray(4096, '\1'), rev);
    c.deliverPage(body, QByteArray(4096, '\x41'), QByteArray(4096, '\1'), rev);
    c.deliverUnreadable({body - 4096, 1, 0}, rev);
    c.show(); c.scrollToAddress(body, HexCanvas::ScrollAlign::Center); draw(c);
    const auto initialY = c.cellRect(body, HexCanvas::ActivePane::Hex).top();
    check(initialY > 60, "known fragment starts below unknown rows");
    for (std::uint64_t page = 2; page <= 24; ++page) {
        c.deliverUnreadable({body - page * 4096, 1, 0}, rev); draw(c);
        check(c.cellRect(body, HexCanvas::ActivePane::Hex).top() == initialY,
            "upstream unreadable page merging keeps known fragment at the same screen row");
    }
    for (std::uint64_t page = 25; page <= 28; ++page) {
        c.setFirstVisibleRow(c.firstVisibleRow() - 1);
        const auto y = c.cellRect(body, HexCanvas::ActivePane::Hex).top();
        c.deliverUnreadable({body - page * 4096, 1, 0}, rev); draw(c);
        check(c.cellRect(body, HexCanvas::ActivePane::Hex).top() == y,
            "upward user scroll is preserved when its next page is folded");
    }

    HexCanvas unknown;
    unknown.resize(900, 420); unknown.setFoldUnknownRegions(true);
    unknown.setAddressSpace(0, body + 0x7FFF);
    const auto unknownRev = unknown.sourceRevision();
    unknown.deliverUnreadable({body - 4096, 1, 0}, unknownRev);
    unknown.show(); unknown.scrollToAddress(body - 0x1800, HexCanvas::ScrollAlign::Top); drain();
    unknown.setFirstVisibleRow(unknown.firstVisibleRow() - 3);
    const auto oldFirst = unknown.visibleAddressRange()->first;
    unknown.deliverUnreadable({body - 8192, 1, 0}, unknownRev); draw(unknown);
    check(unknown.visibleAddressRange()->first <= oldFirst,
        "all-unknown upward view resolves toward the preceding boundary");

    HexCanvas late;
    late.resize(900, 420); late.setFoldUnknownRegions(true);
    late.setAddressSpace(0, body + 0x7FFF); late.show();
    late.deliverPage(body - 0x100000, QByteArray(4096, '\x31'), QByteArray(4096, '\1'), late.sourceRevision());
    late.scrollToAddress(body, HexCanvas::ScrollAlign::Center); drain();
    late.deliverPage(body, QByteArray(4096, '\x42'), QByteArray(4096, '\1'), late.sourceRevision());
    const auto lateY = late.cellRect(body, HexCanvas::ActivePane::Hex).top();
    late.deliverUnreadable({body - 4096, 1, 0}, late.sourceRevision()); draw(late);
    check(late.cellRect(body, HexCanvas::ActivePane::Hex).top() == lateY,
        "newly landed readable fragment becomes an anchor before adjacent unreadable pages finish");

    // User's exact six-row example, with the caret in the trailing valid fragment.
    HexCanvas example;
    example.resize(900, 420); example.setFoldUnknownRegions(true);
    example.setAddressSpace(0, 457 * 16 - 1);
    const auto exampleRev = example.sourceRevision();
    QByteArray front(4096, '\0'), frontMask(4096, '\0');
    std::fill(front.begin(), front.begin() + 16, '\xAB');
    std::fill(front.begin() + 16, front.begin() + 32, '\xCD');
    std::fill(frontMask.begin(), frontMask.begin() + 32, '\1');
    QByteArray back(4096, '\0'), backMask(4096, '\0');
    for (int i = 456 * 16 - 16; i < 457 * 16; ++i) {
        back[i - 4096] = i < 456 * 16 ? '\xAC' : '\xBD'; backMask[i - 4096] = '\1';
    }
    example.deliverPage(4096, back, backMask, exampleRev);
    example.setCaretAddress(455 * 16);
    example.deliverPage(0, front, frontMask, exampleRev);
    example.show(); example.scrollToAddress(455 * 16, HexCanvas::ScrollAlign::Center); draw(example);
    const std::uint64_t addresses[] = {0, 16, 32, 454 * 16, 455 * 16, 456 * 16};
    const int height = example.cellRect(0, HexCanvas::ActivePane::Hex).height();
    const int top = example.cellRect(0, HexCanvas::ActivePane::Hex).top();
    for (int i = 0; i < 6; ++i) {
        const auto cell = example.cellRect(addresses[i], HexCanvas::ActivePane::Hex);
        check(!cell.isNull() && cell.top() == top + i * height, "six-row example keeps original addresses in visual order");
        check(example.addressForViewportPos(cell.center()) == addresses[i], "six-row example hit testing");
    }
    check(example.cellStateAt(0).value == 0xAB && example.cellStateAt(16).value == 0xCD
        && example.cellStateAt(455 * 16).value == 0xAC && example.cellStateAt(456 * 16).value == 0xBD,
        "both meaningful fragments preserve their original values");
    check(example.cellStateAt(32).byteState == HexCanvas::ByteState::Unreadable
        && example.cellStateAt(454 * 16).byteState == HexCanvas::ByteState::Unreadable,
        "only the first and last unknown rows remain");
    check(example.cellRect(300 * 16, HexCanvas::ActivePane::Hex).isNull()
        && example.caretAddress() == 455 * 16 && example.selectedRange()->first == 455 * 16,
        "interior unknown rows hidden while trailing caret and selection are unchanged");

    HexCanvas dots;
    dots.resize(900, 420); dots.setFoldUnknownRegions(true);
    dots.setAddressSpace(0, UINT64_MAX); dots.show(); draw(dots);
    check(dots.lastPaintedRowCount() == 2 && dots.cellStateAt(0).byteState == HexCanvas::ByteState::NotLoaded,
        "unloaded dots collapse to two rows without becoming unreadable or zero");
    dots.scrollToAddress(body, HexCanvas::ScrollAlign::Center); draw(dots);
    check(!dots.cellRect(body, HexCanvas::ActivePane::Hex).isNull(), "explicit navigation reveals a row inside a folded dot region");
    dots.deliverPage(0, QByteArray(4096, '\x10'), QByteArray(4096, '\1'), dots.sourceRevision()); draw(dots);
    check(!dots.cellRect(body, HexCanvas::ActivePane::Hex).isNull(),
        "unrelated readable page cannot steal the explicitly revealed navigation target");
    const auto dotY = dots.cellRect(body, HexCanvas::ActivePane::Hex).top();
    dots.deliverPage(body, QByteArray(4096, '\x77'), QByteArray(4096, '\1'), dots.sourceRevision()); draw(dots);
    check(dots.cellStateAt(body).value == 0x77 && dots.cellRect(body, HexCanvas::ActivePane::Hex).top() == dotY,
        "newly read values expand folded dots around a stable target");
    dots.refresh(); draw(dots);
    check(!dots.cellRect(body, HexCanvas::ActivePane::Hex).isNull(), "refresh retains and requests the viewed address after it becomes unloaded");
    dots.setFoldUnknownRegions(false); dots.scrollToAddress(body, HexCanvas::ScrollAlign::Center);
    dots.setFoldUnknownRegions(true); draw(dots);
    check(!dots.cellRect(body, HexCanvas::ActivePane::Hex).isNull(), "enabling folding retains the viewed unloaded address");
}
void features() {
    ksword::memwb::MemoryDiffOverlay edits;
    edits.LoadBaseline("fold-test", 0x1000, std::vector<std::uint8_t>(64,0), std::vector<std::uint8_t>(64,1));
    edits.Stage(0x1004, {1,2}); edits.Stage(0x1020, {3,4,5});
    check(!edits.FirstPendingRange(0,0x1003), "pending-range lookup skips a disjoint prefix");
    auto range = edits.FirstPendingRange(0x1005,0x1010);
    check(range && range->first == 0x1004 && range->last == 0x1005, "pending-range lookup finds a block containing the query start");
    range = edits.FirstPendingRange(0x1006,0x1020);
    check(range && range->first == 0x1020 && range->last == 0x1022, "pending-range lookup advances to the next block");
    check(!edits.FirstPendingRange(0x1023,UINT64_MAX), "pending-range lookup ends after the last block");
    HexCanvas staged;
    staged.resize(900, 420); staged.setFoldUnknownRegions(true); staged.setAddressSpace(0,UINT64_MAX);
    staged.setOverlay(&edits); staged.show(); staged.scrollToAddress(0x1004); draw(staged);
    check(staged.cellStateAt(0x1004).value == 1 && !staged.cellRect(0x1004,HexCanvas::ActivePane::Hex).isNull(),
        "staged values survive inside an uncached folded dot region");
    staged.setOverlay(nullptr);
    ks::ui::WorkbenchStatusBar footer(std::make_unique<Diagnostics>());
    footer.setDrawerExpanded(true); footer.resize(700, 240); footer.show(); drain();
    auto* fold = footer.findChild<QCheckBox*>(QStringLiteral("workbench_fold_unknown"));
    auto* wrap = footer.findChild<QCheckBox*>(QStringLiteral("workbench_wrap"));
    check(fold && fold->isChecked() && footer.foldUnknownRegions(), "folding checkbox defaults on");
    if (!wrap) for (auto* box : footer.findChildren<QCheckBox*>()) if (box != fold) wrap = box;
    check(wrap && fold->y() == wrap->y() && fold->x() > wrap->x(), "folding follows word wrap");
    int toggles = 0;
    QObject::connect(&footer, &ks::ui::WorkbenchStatusBar::foldUnknownRegionsChanged, &footer, [&](bool) { ++toggles; });
    footer.setFoldUnknownRegions(false);
    check(!fold->isChecked() && toggles == 1, "persisted toggle reaches the canvas contract");
    footer.resize(240, 260); drain();
    check(fold->geometry().right() < fold->parentWidget()->width(), "narrow footer wraps controls");
    footer.hide();
    HexCanvas c;
    c.resize(900, 420);
    c.setFoldUnknownRegions(true);
    c.setUniformBoundaryNavigationEnabled(true);
    QByteArray data(2 * 1024 * 1024, '\x51');
    std::fill(data.begin() + 0x10000, data.begin() + 0x90000, '\0');
    c.setStaticData(0, data);
    c.show(); drain();
    c.scrollToAddress(0x40000, HexCanvas::ScrollAlign::Center); draw(c);
    auto* up = button(c, QStringLiteral("上界"));
    auto* down = button(c, QStringLiteral("下界"));
    check(up && down && up->isVisible() && down->isVisible(), "uniform screen exposes both bounds");
    check(up->toolButtonStyle() == Qt::ToolButtonIconOnly && down->toolButtonStyle() == Qt::ToolButtonIconOnly,
        "boundary actions display icons instead of text");
    check(!up->icon().pixmap(16,16).isNull() && !down->icon().pixmap(16,16).isNull()
        && up->size() == QSize(28,28) && down->size() == QSize(28,28), "real SVG icons and shared compact button metrics");
    check(!up->toolTip().isEmpty() && !down->accessibleName().isEmpty(), "icon actions retain tooltip and accessible names");
    check(up->x() > c.viewport()->width() / 2 && up->y() < c.viewport()->height() / 2, "upper button top right");
    check(down->x() > c.viewport()->width() / 2 && down->y() > c.viewport()->height() / 2, "lower button bottom right");
    QTest::mouseClick(up, Qt::LeftButton); drain(); draw(c);
    const auto upperCell = c.cellRect(0x10000, HexCanvas::ActivePane::Hex);
    check(!upperCell.isNull() && std::abs(upperCell.center().y() - c.viewport()->height() / 2) < 40, "first uniform row centered");
    check(!up->isVisible() && !down->isVisible(), "mixed screen hides bound buttons");
    c.scrollToAddress(0x40000, HexCanvas::ScrollAlign::Center); draw(c);
    QTest::mouseClick(down, Qt::LeftButton); drain(); draw(c);
    const auto lowerCell = c.cellRect(0x8fff0, HexCanvas::ActivePane::Hex);
    check(!lowerCell.isNull() && std::abs(lowerCell.center().y() - c.viewport()->height() / 2) < 40, "last uniform row centered");
    c.scrollToAddress(0x40000, HexCanvas::ScrollAlign::Center); draw(c);
    QTest::mouseClick(up, Qt::LeftButton);
    c.setStaticData(0x1000, QByteArray(8192, '\x31')); drain(); draw(c);
    check(c.addressSpaceRange()->first == 0x1000, "source replacement cancels old scan");

    HexCanvas hole;
    hole.resize(900, 420);
    hole.setFoldUnknownRegions(true);
    hole.setUniformBoundaryNavigationEnabled(true);
    hole.setAddressSpace(0, 0x200fff);
    const auto rev = hole.sourceRevision();
    hole.deliverUnreadableExtent(0x1000, 0x1fffff, rev);
    hole.deliverPage(0, QByteArray(4096, '\x12'), QByteArray(4096, '\1'), rev);
    hole.deliverPage(0x200000, QByteArray(4096, '\x34'), QByteArray(4096, '\1'), rev);
    hole.show(); hole.scrollToAddress(0xff0); draw(hole);
    const auto first = hole.cellRect(0x1000, HexCanvas::ActivePane::Hex);
    const auto last = hole.cellRect(0x1ffff0, HexCanvas::ActivePane::Hex);
    check(!first.isNull() && !last.isNull() && last.top() - first.top() == first.height(), "hole keeps adjacent first and last row");
    check(hole.cellRect(0x100000, HexCanvas::ActivePane::Hex).isNull(), "hidden byte has no phantom cell");
    check(hole.addressForViewportPos(last.center()) == 0x1ffff0, "hit testing uses original address");
    const auto spans = hole.visibleAddressSpans();
    check(spans.size() == 2 && spans.front().last == 0x100F && spans.back().first == 0x1FFFF0,
        "reread spans skip the hidden physical interval");
    check(!button(hole, QStringLiteral("上界"))->isVisible(), "unreadable bytes never count as pure zero");
    const auto center = hole.visibleCenterAddress();
    check(center && !hole.cellRect(*center, HexCanvas::ActivePane::Hex).isNull()
        && std::abs(hole.cellRect(*center, HexCanvas::ActivePane::Hex).center().y() - hole.viewport()->height() / 2) < 40,
        "baseline center follows visual rows");
    hole.scrollToAddress(0x100000, HexCanvas::ScrollAlign::Center); draw(hole);
    check(!hole.cellRect(0x100000, HexCanvas::ActivePane::Hex).isNull(), "explicit address navigation reveals hidden row");
    hole.setFoldUnknownRegions(false); hole.scrollToAddress(0x1000); draw(hole);
    check(!hole.cellRect(0x1010, HexCanvas::ActivePane::Hex).isNull(), "disable restores all rows");
    HexCanvas bounded;
    UnreadableProvider provider;
    provider.canvas = &bounded;
    bounded.resize(900, 420);
    bounded.setFoldUnknownRegions(true);
    bounded.setAddressSpace(0, UINT64_MAX);
    bounded.setPageProvider(&provider);
    bounded.show(); drain(); draw(bounded);
    check(provider.folding && provider.pages <= 16, "unmapped source cannot walk address space automatically");
    const auto before = provider.pages;
    for (int i = 0; i < 20; ++i) draw(bounded);
    check(provider.pages == before, "idle paint issues no extra reads");
    bounded.scrollToAddress(0x10000000); drain(); draw(bounded);
    check(provider.pages > before && provider.pages <= before + 16, "user navigation gets a bounded new read budget");
    check(std::any_of(provider.requests.begin(), provider.requests.end(), [](const auto& range) {
        return range.firstPageStart <= 0x10000000 && (0x10000000 - range.firstPageStart) / 4096 < range.pageCount;
    }), "navigation actually requests the target page inside a folded dot region");
    bounded.setPageProvider(nullptr);
    bounded.setStaticData(0x1000, QByteArray(16384, '\x22'));
    check(bounded.firstVisibleRow() == 0, "new source does not inherit the old fold anchor");
    std::printf("NAVIGATION_CHECKS=%d\n", checks);
}
#endif

void benchmark(bool uniform) {
    HexCanvas c;
    c.resize(1100, 650);
#ifdef HEX_VIEW_FEATURES
    c.setFoldUnknownRegions(true);
    c.setUniformBoundaryNavigationEnabled(true);
    c.setOverviewEnabled(true);
#endif
    QByteArray data(2 * 1024 * 1024, '\0');
    if (!uniform) for (qsizetype i = 0; i < data.size(); ++i) data[i] = static_cast<char>(i % 251);
    c.setStaticData(0, data); c.show(); drain();
    for (int i = 0; i < 20; ++i) { c.scrollToAddress(0x10000 + i * 16); c.viewport()->repaint(); }
    drain();
    std::vector<double> samples;
    for (int batch = 0; batch < 7; ++batch) {
        QElapsedTimer timer; timer.start();
        for (int i = 0; i < 100; ++i) {
            c.scrollToAddress(0x10000 + static_cast<std::uint64_t>((i * 7 + batch * 11) % 800) * 16);
            c.viewport()->repaint();
            QApplication::processEvents();
        }
        samples.push_back(timer.nsecsElapsed() / 1000000.0 / 100.0);
    }
    std::sort(samples.begin(), samples.end());
    std::printf("BENCH_%s_MEDIAN_MS=%.4f MIN_MS=%.4f MAX_MS=%.4f\n", uniform ? "ZERO" : "MIXED", samples[3], samples.front(), samples.back());
}
int main(int argc, char** argv) {
    QApplication app(argc, argv);
    QFontDatabase::addApplicationFont(QStringLiteral("C:/Windows/Fonts/consola.ttf"));
    QFontDatabase::addApplicationFont(QStringLiteral("C:/Windows/Fonts/msyh.ttc"));
    app.setFont(QFont(QStringLiteral("Microsoft YaHei"), 10));
#ifdef HEX_VIEW_FEATURES
    if (app.arguments().contains(QStringLiteral("--overview-only"))) { runHexOverviewUiTests(); std::printf("OVERVIEW_UI_CHECKS=%d\n", checks); return 0; }
    if (app.arguments().contains(QStringLiteral("--fold-stability"))) { foldScrollStability(); return 0; }
    if (!app.arguments().contains(QStringLiteral("--bench-only"))) { foldScrollStability(); features(); runHexOverviewUiTests(); std::printf("TOTAL_UI_CHECKS=%d\n", checks); }
#endif
    benchmark(false); benchmark(true);
    return 0;
}
