// Real professional canvas controls; no native application/clipboard access.
#include "HexCanvas.h"
#include "HexCanvasFormat.h"
#include "../../Ksword5.1/Ksword5.1/theme.h"
#include <QApplication>
#include <QCoreApplication>
#include <QFontMetrics>
#include <QScrollBar>
#include <QTest>
#include <QToolButton>
#include <QWheelEvent>
#include <algorithm>

using ks::ui::HexCanvas;
namespace fmt = ks::ui::hexcanvas_format;
void check(bool value, const char* text);
void drain();

namespace {
class Reads final : public ks::ui::IHexPageProvider {
public:
    std::uint64_t pages = 0;
    void RequestPages(const std::vector<ks::ui::HexFetchRange>& ranges, std::uint64_t) override {
        for (const auto& range : ranges) pages += range.pageCount;
    }
};
QToolButton* toggle(HexCanvas& c) { return c.findChild<QToolButton*>(QStringLiteral("memwb_address_collapse")); }
QString expectedPrefix(const HexCanvas& c) {
    const auto visible = c.visibleAddressRange().value();
    const auto width = static_cast<std::uint64_t>(c.bytesPerRow());
    const int digits = c.addressSpaceRange()->last <= UINT32_MAX ? 8 : 16;
    const auto first = fmt::FormatAddress(visible.first - visible.first % width, digits);
    const auto last = fmt::FormatAddress(visible.last - visible.last % width, digits);
    const auto mismatch = std::mismatch(first.begin(), first.end(), last.begin(), last.end());
    const auto size = std::min<qsizetype>(mismatch.first - first.begin(), first.size() - 1);
    return first.left(size);
}
void wheel(HexCanvas& c) {
    QWheelEvent event(QPointF(250,100), QPointF(c.viewport()->mapToGlobal(QPoint(250,100))),
        QPoint(), QPoint(0,-120), Qt::NoButton, Qt::NoModifier, Qt::NoScrollPhase, false);
    QApplication::sendEvent(c.viewport(), &event); drain();
}
}

void runHexAddressColumnTests() {
    check(fmt::CommonAddressPrefix(0xF10,0xF20,5)==QStringLiteral("0x00F"), "address prefix follows the user's exact split");
    check(fmt::FormatAddressSuffix(0xF10,5,QStringLiteral("0x00F"))==QStringLiteral("10")
        && fmt::FormatAddressSuffix(0xF20,5,QStringLiteral("0x00F"))==QStringLiteral("20"), "rows show only 10 / 20, without repeating F");
    check(fmt::CommonAddressPrefix(0xFF0,0x1000,8)==QStringLiteral("0x0000"), "prefix retreats across a carry into the next address digit");
    check(fmt::FormatAddressSuffix(0x1234,8,QStringLiteral("0xAB"))==QStringLiteral("0x00001234"), "a mismatched prefix cannot silently corrupt the displayed address");
    check(fmt::FormatAddressSuffix(0x1234,8,QString())==QStringLiteral("0x00001234"), "expanded addresses keep 0x and leading zeroes");
    const auto single = fmt::CommonAddressPrefix(UINT64_MAX,UINT64_MAX,16);
    check(single+fmt::FormatAddressSuffix(UINT64_MAX,16,single)==fmt::FormatAddress(UINT64_MAX,16)
        && fmt::FormatAddressSuffix(UINT64_MAX,16,single)==QStringLiteral("F"), "a one-row viewport still retains one digit at UINT64_MAX");

    Reads reads;
    HexCanvas c;
    c.resize(800,300); c.setViewportReadEnabled(false); c.setPageProvider(&reads);
    check(!toggle(c) && !c.addressColumnCollapsed(), "generic HEX hosts do not allocate an address toggle by default");
    c.setAddressColumnCollapseEnabled(true); c.setAddressSpace(0xF10,0xF2F);
    c.deliverPage(0,QByteArray(4096,'A'),QByteArray(4096,'\1'),c.sourceRevision()); c.show(); drain();
    auto* button = toggle(c);
    check(button && button->isVisible() && button->size()==QSize(28,28) && button->iconSize()==QSize(16,16), "address header action uses shared compact icon metrics");
    check(button->toolButtonStyle()==Qt::ToolButtonIconOnly && !button->icon().pixmap(16,16).isNull()
        && !button->toolTip().isEmpty() && !button->accessibleName().isEmpty(), "address action has a real chevron, help and accessible name");
    const auto expandedIcon = button->icon().cacheKey();
    const auto originalCell = c.cellRect(0xF10,HexCanvas::ActivePane::Hex);
    const auto originalWidth = c.sizeHint().width();
    c.setCaretAddress(0xF12,false,false); c.setCaretAddress(0xF24,true,false);
    const auto selected = c.selectedRange(); const auto revision = c.sourceRevision(), beforeReads = reads.pages;
    QTest::mouseClick(button,Qt::LeftButton); drain();
    const auto compactCell = c.cellRect(0xF10,HexCanvas::ActivePane::Hex);
    check(c.addressColumnCollapsed() && c.addressColumnPrefix()==QStringLiteral("0x00000F"), "header owns the complete common prefix of visible row addresses");
    check(compactCell.left()<originalCell.left() && c.sizeHint().width()<originalWidth, "collapsing actually narrows the address gutter and moves byte columns left");
    check(c.sourceRevision()==revision && c.selectedRange()==selected && reads.pages==beforeReads, "address presentation does not change source, selection or memory reads");
    check(button->icon().cacheKey()!=expandedIcon && button->toolTip().contains(c.addressColumnPrefix()), "collapsed action points right and retains the full prefix in its tooltip");
    check(button->geometry().right()<compactCell.left() && button->geometry().bottom()<compactCell.top(), "header arrow stays inside the top-left cell");
    check(c.addressForViewportPos(compactCell.center())==0xF10, "byte hit testing still returns the full address after shrinking the gutter");
    QByteArray bytes; QString reason;
    check(c.selectedBytes(&bytes,&reason) && bytes==QByteArray(19,'A'), "copy source stays the full selected byte range, independent of address suffixes");
    const int cw=QFontMetrics(c.font()).horizontalAdvance(QLatin1Char('0'));
    QTest::mouseClick(c.viewport(),Qt::LeftButton,Qt::NoModifier,QPoint(cw*2,compactCell.center().y()));
    check(c.selectedRange() && c.selectedRange()->first==0xF10 && c.selectedRange()->last==0xF1F, "clicking a compact address still selects the complete original row");
    check(!c.addressForViewportPos(QPoint(cw*2,compactCell.center().y())), "compact address digits never masquerade as byte cells");
    button->setFocus(Qt::TabFocusReason); QTest::keyClick(button,Qt::Key_Space); drain();
    check(!c.addressColumnCollapsed() && c.addressColumnPrefix().isEmpty() && c.cellRect(0xF10,HexCanvas::ActivePane::Hex).left()==originalCell.left(), "keyboard activation expands back to the original zero-padded layout");

    c.setViewportReadEnabled(true);
    c.setStaticData(0xFFF0,QByteArray(32768,'A')); c.setAddressColumnCollapsed(true); drain();
    const auto firstPrefix=c.addressColumnPrefix();
    c.verticalScrollBar()->setValue(100); drain();
    check(c.addressColumnPrefix()==expectedPrefix(c) && c.addressColumnPrefix()!=firstPrefix, "native scrollbar navigation updates the visible common prefix before painting");
    wheel(c);
    check(c.addressColumnPrefix()==expectedPrefix(c), "wheel navigation shares the same address prefix geometry");
    c.scrollToAddress(0x11000,HexCanvas::ScrollAlign::Top); drain();
    check(c.addressColumnPrefix()==expectedPrefix(c) && c.addressForViewportPos(c.cellRect(0x11000,HexCanvas::ActivePane::Hex).center())==0x11000,
        "address jumps update both suffix layout and byte hit testing");
    c.setBytesPerRow(64); c.resize(450,300); drain();
    c.horizontalScrollBar()->setValue(0);drain();
    const auto visibleFirst=c.visibleAddressRange()->first;
    const int gutter=c.cellRect(visibleFirst,HexCanvas::ActivePane::Hex).left()-cw;
    const auto unscrolled=c.viewport()->grab().toImage();
    c.horizontalScrollBar()->setValue(c.horizontalScrollBar()->maximum()); drain();
    const auto scrolled=c.viewport()->grab().toImage();
    const int gutterPixels=qRound(gutter*unscrolled.devicePixelRatio());
    check(unscrolled.copy(0,0,gutterPixels,unscrolled.height())==scrolled.copy(0,0,gutterPixels,scrolled.height()),
        "compact suffixes, prefix header and arrow remain pixel-stable during horizontal scrolling");
    check(c.addressColumnPrefix()==expectedPrefix(c) && button->geometry().right()<c.viewport()->width(), "prefix and arrow stay fixed during horizontal scrolling");
    const auto automatic=c.bytesPerRow(); c.setAddressColumnCollapsed(false);c.setAutoBytesPerRow(true);drain();
    const auto fitted=c.bytesPerRow(); c.setAddressColumnCollapsed(true);drain();
    check(c.bytesPerRow()==fitted && automatic==64, "collapsing preserves the original auto-fit budget instead of causing row-width oscillation");
    for (int zoom : {-2,3,0}) { c.setZoomLevel(zoom); drain(); check(c.addressColumnPrefix()==expectedPrefix(c), "font zoom keeps address prefix and visible row geometry aligned"); }
    c.resize(140,220); drain();
    check(!button->isVisible() || button->geometry().right()<c.viewport()->width(), "very narrow views do not put the toggle over the byte area");

    const bool dark=KswordTheme::IsDarkModeEnabled();
    c.setStaticData(0x7FF7CC05EEF8ULL,QByteArray(32768,'\0'));c.setBytesPerRow(8);c.setAutoBytesPerRow(false);c.resize(600,310);drain();
    for(bool mode : {false,true}) {
        KswordTheme::SetDarkModeEnabled(mode); c.viewport()->repaint(); drain();
        check(c.addressColumnPrefix()==expectedPrefix(c) && !button->icon().pixmap(16,16).isNull(), "64-bit prefix and SVG action survive both theme palettes");
        c.grab().save(QCoreApplication::applicationDirPath()+(mode ? QStringLiteral("/hex-address-collapse-dark.png") : QStringLiteral("/hex-address-collapse-light.png")));
    }
    KswordTheme::SetDarkModeEnabled(dark);
    c.setStaticData(UINT64_MAX-31,QByteArray(32,'A'));drain();
    check(c.addressColumnPrefix()==expectedPrefix(c), "collapsed 64-bit addresses do not wrap at the final row");
    c.clearAddressSpace(); drain();
    check(!button->isVisible() && c.addressColumnPrefix().isEmpty(), "clearing the target hides the action and removes the old prefix");
    c.setStaticData(0x10,QByteArray(32,'A'));drain();
    check(c.addressColumnCollapsed() && c.addressColumnPrefix()==expectedPrefix(c), "a new 32-bit target replaces the previous 64-bit prefix");
    c.setAddressColumnCollapseEnabled(false);drain();
    check(!button->isVisible() && !c.addressColumnCollapsed() && c.addressColumnPrefix().isEmpty(), "disabling the optional header control restores the generic layout");

    HexCanvas folded;
    constexpr std::uint64_t far=1ULL<<44;
    folded.resize(900,380);folded.setViewportReadEnabled(false);folded.setFixedAddressScale(true);
    folded.setFoldUnknownRegions(true);folded.setAddressColumnCollapseEnabled(true);folded.setOverviewEnabled(true);
    folded.setAddressSpace(0,far+8191);
    for(auto address : {0ULL,far}) folded.deliverPage(address,QByteArray(4096,'A'),QByteArray(4096,'\1'),folded.sourceRevision());
    folded.show();drain();const auto maxKnown=folded.verticalScrollBar()->maximum();
    const auto foldedSelection=folded.selectedRange();folded.setAddressColumnCollapsed(true);drain();
    check(folded.verticalScrollBar()->maximum()==maxKnown && folded.selectedRange()==foldedSelection,
        "address collapsing preserves the known-only axis and selection across a folded 16TiB hole");
    folded.verticalScrollBar()->setValue(300);drain();
    check(folded.addressColumnPrefix()==expectedPrefix(folded) && folded.visibleAddressRange()->first>=far,
        "native known-only scrolling updates the prefix for the far fragment");
    folded.verticalScrollBar()->setValue(maxKnown);wheel(folded);
    check(folded.verticalScrollBar()->value()==maxKnown && folded.addressColumnPrefix()==expectedPrefix(folded),
        "collapsed addresses preserve the known-only last screen and wheel endpoint");

    HexCanvas proportional;
    proportional.resize(700,310);proportional.setAddressColumnCollapseEnabled(true);
    proportional.setAddressSpace(0,UINT64_MAX);proportional.setAddressColumnCollapsed(true);proportional.show();drain();
    const int wanted=proportional.verticalScrollBar()->maximum()/2+123;
    proportional.verticalScrollBar()->setValue(wanted);drain();
    check(proportional.verticalScrollBar()->value()==wanted && proportional.addressColumnPrefix()==expectedPrefix(proportional),
        "64-bit proportional thumb movement refreshes the prefix without writing a rounded value back to the thumb");
}
