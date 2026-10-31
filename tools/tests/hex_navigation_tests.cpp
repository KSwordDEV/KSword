// Real HexCanvas component checks and a repeatable paint/scroll benchmark.
// No target-process IO, native app automation or clipboard access.
#include "HexCanvas.h"
#include <QApplication>
#include <QElapsedTimer>
#include <QScrollBar>
#include <QToolButton>
#include <QTest>
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#ifdef HEX_VIEW_FEATURES
#include "WorkbenchStatusBar.h"
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
    void SetUnknownFoldingEnabled(bool enabled) override { folding = enabled; }
    void RequestPages(const std::vector<ks::ui::HexFetchRange>& ranges, std::uint64_t revision) override {
        for (const auto& range : ranges) {
            pages += range.pageCount;
            canvas->deliverUnreadable(range, revision);
        }
    }
};
QToolButton* button(HexCanvas& c, const QString& text) {
    for (auto* b : c.findChildren<QToolButton*>()) if (b->text() == text) return b;
    return nullptr;
}
void features() {
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
    app.setFont(QFont(QStringLiteral("Microsoft YaHei"), 10));
#ifdef HEX_VIEW_FEATURES
    if (!app.arguments().contains(QStringLiteral("--bench-only"))) features();
#endif
    benchmark(false); benchmark(true);
    return 0;
}
