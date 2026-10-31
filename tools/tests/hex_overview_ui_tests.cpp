#include "HexCanvas.h"
#include "HexCanvasOverviewBar.h"
#include "HexCanvasFormat.h"
#include <QApplication>
#include <QCoreApplication>
#include <QScrollBar>
#include <QStyleOptionSlider>
#include <QWheelEvent>
#include <QFontMetrics>
#include <QTest>
#include <cmath>
#include <cstdio>

using ks::ui::HexCanvas;
using Rail = ks::ui::HexCanvasOverviewBar;
void check(bool value, const char* text);
void drain();
void draw(HexCanvas& canvas);
namespace {
class ReadCounter final : public ks::ui::IHexPageProvider {
public:
    std::uint64_t requests=0;
    void RequestPages(const std::vector<ks::ui::HexFetchRange>& ranges,std::uint64_t) override {
        for(const auto& range:ranges) requests+=range.pageCount;
    }
};
Rail* rail(HexCanvas& c) { return static_cast<Rail*>(c.findChild<QWidget*>(QStringLiteral("memwb_hex_overview"))); }
QImage capture(Rail& r) { r.repaint(); drain(); return r.grab().toImage(); }
QColor pixel(const QImage& image,int x,int y) {
    const auto dpr=image.devicePixelRatio();
    return image.pixelColor(qRound(x*dpr),qRound(y*dpr));
}
int colorDistance(QColor a,QColor b) {
    return std::abs(a.red()-b.red())+std::abs(a.green()-b.green())+std::abs(a.blue()-b.blue());
}
double luminance(QColor c) {
    const auto linear=[](double x){return x<=0.04045 ? x/12.92 : std::pow((x+0.055)/1.055,2.4);};
    return .2126*linear(c.redF())+.7152*linear(c.greenF())+.0722*linear(c.blueF());
}
}
void runFixedAddressUiTests() {
    const auto wheel=[](HexCanvas& c) {
        QWheelEvent event(QPointF(300,100),QPointF(c.viewport()->mapToGlobal(QPoint(300,100))),QPoint(),QPoint(0,-120),
            Qt::NoButton,Qt::NoModifier,Qt::NoScrollPhase,false);
        QApplication::sendEvent(c.viewport(),&event);drain();
    };
    HexCanvas fixed;
    constexpr std::uint64_t size=1ULL<<20, middle=size/2;
    fixed.resize(700,420);fixed.setFixedAddressScale(true);fixed.setFoldUnknownRegions(true);
    fixed.setOverviewEnabled(true);fixed.setAddressSpace(0,size-1);
    for(auto address:{0ULL,middle,size*3/4}) fixed.deliverPage(address,QByteArray(4096,'A'),QByteArray(4096,'\1'),fixed.sourceRevision());
    fixed.setCaretAddress(middle,false,false);fixed.show();drain();auto* r=rail(fixed);
    auto image=capture(*r);const int center=r->width()/2,y=qRound(r->rowPosition(middle/16));
    const auto tint=pixel(image,center,y);const auto maximum=fixed.verticalScrollBar()->maximum();
    check(maximum==static_cast<int>(size/16-fixed.visibleRowCount()),"fixed native scrollbar covers the complete address range");
    check(tint!=Qt::white,"a cached distant fragment appears in the full-address preview");
    const auto marker=r->caretPosition();
    fixed.deliverPage(size/4,QByteArray(4096,'\xFF'),QByteArray(4096,'\1'),fixed.sourceRevision());
    image=capture(*r);
    check(fixed.verticalScrollBar()->maximum()==maximum && std::abs(r->caretPosition()-marker)<.01,
        "newly expanded data does not change the scrollbar range or move address marks");
    check(pixel(image,center,y)==tint,"newly read data leaves existing preview colors at the same address position");
    const auto builds=r->summaryBuildCount();
    wheel(fixed);capture(*r);
    fixed.setFoldUnknownRegions(false);capture(*r);
    fixed.setFoldUnknownRegions(true);image=capture(*r);
    check(r->summaryBuildCount()==builds && fixed.verticalScrollBar()->maximum()==maximum,
        "scrolling and folding change markers without remapping fixed-address statistics");
    check(pixel(image,center,y)==tint,"folding does not move the distant cached fragment");
    QTest::mouseClick(r,Qt::LeftButton,Qt::NoModifier,QPoint(center,y));drain();
    check(!fixed.cellRect(middle,HexCanvas::ActivePane::Hex).isNull(),"fixed overview click reveals the corresponding address");
    fixed.verticalScrollBar()->setValue(maximum);drain();
    const auto bottom=fixed.firstVisibleRow();wheel(fixed);
    check(fixed.firstVisibleRow()==bottom && fixed.visibleAddressRange()->last==size-1,
        "dragging the native scrollbar to the bottom reaches the actual last screen");
    fixed.deliverPage(size-4096,QByteArray(4096,'B'),QByteArray(4096,'\1'),fixed.sourceRevision());drain();
    check(fixed.verticalScrollBar()->maximum()==maximum && fixed.verticalScrollBar()->value()==maximum
        && fixed.visibleAddressRange()->last==size-1,"accepted end-page reads keep an explicitly selected bottom pinned");
    image=capture(*r);
    const auto endTint=KswordTheme::BlendColors(Qt::white,KswordTheme::PrimaryAccentColor(),qRound(.70*255));
    check(colorDistance(pixel(image,center,r->height()-2),endTint)<4,"viewport markers do not cover the cached color at the end of the full-address overview");
    const auto newBottom=fixed.firstVisibleRow();wheel(fixed);
    check(fixed.firstVisibleRow()==newBottom,"wheel scrolling cannot move beyond the last screen after reads finish");
    fixed.grab().save(QCoreApplication::applicationDirPath()+QStringLiteral("/hex-fixed-address-overview.png"));
    fixed.setAddressSpace(0,8191);drain();
    check(fixed.firstVisibleRow()==0 && fixed.verticalScrollBar()->value()==0,"changing target clears the end pin");

    HexCanvas huge;huge.resize(700,420);huge.setAddressSpace(0,UINT64_MAX);huge.show();drain();
    const auto last=(1ULL<<60)-huge.visibleRowCount();
    huge.setFirstVisibleRow(last-1);
    check(huge.verticalScrollBar()->value()<huge.verticalScrollBar()->maximum(),"a near-end 64-bit row never rounds to the actual scrollbar endpoint");
    huge.verticalScrollBar()->setValue(huge.verticalScrollBar()->maximum());const auto end=huge.firstVisibleRow();wheel(huge);
    check(huge.firstVisibleRow()==last && huge.firstVisibleRow()==end,"proportional dragging and wheel agree on the last screen");

    HexCanvas gutter;constexpr std::uint64_t base=0x7FFC01000000;
    gutter.resize(700,420);gutter.setBytesPerRow(64);gutter.setStaticData(base,QByteArray(8192,'A'));gutter.show();drain();
    const int cw=QFontMetrics(gutter.font()).horizontalAdvance(QLatin1Char('0'));
    const auto cell=gutter.cellRect(base,HexCanvas::ActivePane::Hex);
    const int width=cell.left()-cw;
    const auto before=gutter.viewport()->grab().toImage();
    gutter.horizontalScrollBar()->setValue(gutter.horizontalScrollBar()->maximum());drain();
    const auto after=gutter.viewport()->grab().toImage();
    const int pixels=qRound(width*before.devicePixelRatio());
    check(before.copy(0,0,pixels,before.height())==after.copy(0,0,pixels,after.height()),"horizontal scrolling preserves the full address gutter pixel for pixel");
    check(ks::ui::hexcanvas_format::FormatAddress(base,16)==QStringLiteral("0x00007FFC01000000")
        && ks::ui::hexcanvas_format::FormatAddress(0x12,8)==QStringLiteral("0x00000012"),"address display keeps its prefix and zero-padded width");
    check(!gutter.addressForViewportPos(QPoint(cw*3,cell.center().y())),"fixed address gutter is never hit-tested as scrolled byte data");
    QTest::mouseClick(gutter.viewport(),Qt::LeftButton,Qt::NoModifier,QPoint(cw*3,cell.center().y()));
    check(gutter.selectedRange() && gutter.selectedRange()->first==base && gutter.selectedRange()->last==base+63,
        "clicking a fixed gutter still selects the original row");
    gutter.setCaretAddress(base,false,true);
    check(gutter.cellRect(base,HexCanvas::ActivePane::Hex).left()>=width,"revealing a HEX caret scrolls it out from behind the fixed gutter");
    gutter.grab().save(QCoreApplication::applicationDirPath()+QStringLiteral("/hex-fixed-address-gutter.png"));
    gutter.resize(160,420);drain();gutter.setCaretAddress(base,false,true);
    const auto narrow=gutter.cellRect(base,HexCanvas::ActivePane::Hex);
    check(narrow.left()>=0 && narrow.right()<gutter.viewport()->width(),"narrow viewports retain a usable byte area beside the address prefix");
}
void runHexOverviewUiTests() {
    const bool oldDark=KswordTheme::IsDarkModeEnabled();
    HexCanvas c;
    ReadCounter reads;
    auto* const originalBar=c.verticalScrollBar();
    c.resize(700,420); c.setPageProvider(&reads); c.setAddressSpace(0,8191);
    c.deliverPage(0,QByteArray(4096,'\0'),QByteArray(4096,'\1'),c.sourceRevision());
    c.deliverPage(4096,QByteArray(4096,'\x37'),QByteArray(4096,'\1'),c.sourceRevision());
    c.setOverviewEnabled(true);
    check(!rail(c),"overview allocation is deferred until the canvas is visible");
    c.show(); drain(); draw(c);
    auto* r=rail(c);
    check(r && r->isVisible() && r->width()==25,"overview rail is 2.5 times its original 10-pixel width");
    check(c.verticalScrollBar()==originalBar,"original vertical scrollbar identity is retained");
    check(r->geometry().left()==c.viewport()->geometry().right()+1,"rail occupies the right viewport margin");
    check(!r->accessibleName().isEmpty() && !r->toolTip().isEmpty(),"overview has accessible help");
    for(bool dark:{false,true}) {
        KswordTheme::SetDarkModeEnabled(dark);
        r->update(); auto image=capture(*r);
        const int upper=r->height()/4,lower=r->height()*3/4;
        const auto base=pixel(image,0,upper), zero=pixel(image,5,upper), nonzero=pixel(image,5,lower);
        check(1.05/(luminance(base)+.05)>=2.95,"white remains visible against the rail backing in both themes");
        check(zero!=Qt::white && colorDistance(zero,base)>0,"real zero bytes retain a faint theme tint");
        check(colorDistance(nonzero,KswordTheme::PrimaryAccentColor())>20,"even all printable ASCII leaves opacity headroom");
        check(colorDistance(nonzero,Qt::white)>colorDistance(zero,Qt::white),"printable content deepens the light read tint");
        c.grab().save(QCoreApplication::applicationDirPath()+(dark ? QStringLiteral("/overview-dark.png") : QStringLiteral("/overview-light.png")));
    }
    const auto built=r->summaryBuildCount(), readBefore=reads.requests;
    for(int value:{80,120,60,100}) { originalBar->setValue(value); capture(*r); }
    check(r->summaryBuildCount()==built,"ordinary scrolling redraws markers without rebuilding statistics");
    check(reads.requests==readBefore,"overview drawing adds no memory reads");
    KswordTheme::SetDarkModeEnabled(!KswordTheme::IsDarkModeEnabled()); capture(*r);
    check(r->summaryBuildCount()==built,"theme changes repaint colors without rebuilding byte statistics");
    const auto outline=r->viewportOutline();
    const auto expected=1.0+static_cast<double>(c.firstVisibleRow())/512*(r->height()-2);
    check(std::abs(outline.top()-expected)<1,"viewport outline follows the existing projected-row position");
    c.setCaretAddress(300*16,false,false); capture(*r);
    check(std::abs(r->caretPosition()-(1.0+300.5/512*(r->height()-2)))<1,"caret uses the same projected-row scale");
    const int clickY=r->height()*2/3;
    const auto row=r->rowAtPixel(clickY);
    const auto target=row-std::min(row,c.visibleRowCount()/2);
    QTest::mouseClick(r,Qt::LeftButton,Qt::NoModifier,QPoint(5,clickY)); drain();
    check(c.firstVisibleRow()==std::min<std::uint64_t>(target,static_cast<std::uint64_t>(originalBar->maximum())),"overview click uses the existing scrollbar navigation");
    const auto caret=c.caretAddress();
    const auto grab=r->viewportOutline().center().toPoint();
    QTest::mousePress(r,Qt::LeftButton,Qt::NoModifier,grab);
    check(originalBar->isSliderDown(),"overview drag participates in the original scrollbar's drag state");
    QTest::mouseMove(r,QPoint(5,r->height()-5));
    QTest::mouseRelease(r,Qt::LeftButton,Qt::NoModifier,QPoint(5,r->height()-5)); drain();
    check(!originalBar->isSliderDown() && c.firstVisibleRow()>target && c.caretAddress()==caret,"overview drag scrolls without moving the HEX caret");
    originalBar->setValue(0);
    QStyleOptionSlider option; option.initFrom(originalBar); option.orientation=Qt::Vertical;
    option.minimum=0;option.maximum=originalBar->maximum(); option.pageStep=originalBar->pageStep();option.sliderPosition=0;option.sliderValue=0;
    const auto thumb=originalBar->style()->subControlRect(QStyle::CC_ScrollBar,&option,QStyle::SC_ScrollBarSlider,originalBar);
    QTest::mousePress(originalBar,Qt::LeftButton,Qt::NoModifier,thumb.center());
    QTest::mouseMove(originalBar,QPoint(thumb.center().x(),originalBar->height()*3/4));
    QTest::mouseRelease(originalBar,Qt::LeftButton,Qt::NoModifier,QPoint(thumb.center().x(),originalBar->height()*3/4)); drain();
    check(originalBar->value()>0,"original native scrollbar drag remains functional");
    auto rev=c.sourceRevision();
    const auto stableBuilds=r->summaryBuildCount();
    check(c.deliverPage(0,QByteArray(4096,'\x77'),QByteArray(4096,'\1'),rev-1)==HexCanvas::PageResult::RejectedStaleRevision,"stale page is rejected");
    capture(*r);
    check(r->summaryBuildCount()==stableBuilds,"rejected pages do not change the overview");
    c.deliverUnreadable({4096,1,0},rev); auto replaced=capture(*r);
    check(pixel(replaced,5,r->height()*3/4)==Qt::white,"reread failure replaces the previous read color with white");
    const auto hiddenBuilds=r->summaryBuildCount();
    c.hide(); c.deliverPage(4096,QByteArray(4096,'\x55'),QByteArray(4096,'\1'),rev); drain();
    check(r->summaryBuildCount()==hiddenBuilds,"hidden overview defers aggregation and painting");
    c.show(); drain(); capture(*r);
    check(r->summaryBuildCount()>hiddenBuilds,"showing the overview reflects accepted hidden-page updates");
    const auto beforeResizeReads=reads.requests;
    r->resize(r->width(),r->height()-7); capture(*r);
    check(reads.requests==beforeResizeReads,"overview size changes do not read memory");
    c.clearAddressSpace(); auto clear=capture(*r);
    check(pixel(clear,5,r->height()/3)==Qt::white,"clearing the target clears all read colors");
    c.setPageProvider(nullptr);

    HexCanvas mixed;
    mixed.resize(500,300); mixed.setAddressSpace(0,15); mixed.setOverviewEnabled(true);
    QByteArray data(4096,'\0'),valid(4096,'\0');
    std::fill(data.begin(),data.begin()+8,'\x42');std::fill(valid.begin(),valid.begin()+8,'\1');
    mixed.deliverPage(0,data,valid,mixed.sourceRevision());mixed.show();drain();
    auto* mr=rail(mixed);auto mixedImage=capture(*mr);const int y=mr->height()/3;
    const auto asciiTint=KswordTheme::BlendColors(Qt::white,KswordTheme::PrimaryAccentColor(),qRound(.70*255));
    check(colorDistance(pixel(mixedImage,4,y),asciiTint)<4 && pixel(mixedImage,18,y)==Qt::white,
        "mixed bin preserves half unknown white and computes intensity from read bytes alone");
    data.fill('\0');mixed.deliverPage(0,data,valid,mixed.sourceRevision());mixedImage=capture(*mr);
    check(pixel(mixedImage,4,y)!=Qt::white && pixel(mixedImage,18,y)==Qt::white,"mixed real-zero bin keeps its unknown half white");
    data.fill('\x42');valid.fill('\0');std::fill(valid.begin(),valid.begin()+3,'\1');
    mixed.deliverPage(0,data,valid,mixed.sourceRevision());mixedImage=capture(*mr);
    const auto dpr=mixedImage.devicePixelRatio();
    const int left=qRound(mr->stripRect().left()*dpr),right=qRound(mr->stripRect().right()*dpr);
    const double coverage=(right-left)*3.0/16;
    const int whole=static_cast<int>(coverage);
    const auto edgeColor=KswordTheme::BlendColors(Qt::white,asciiTint,qRound((coverage-whole)*255));
    check(colorDistance(mixedImage.pixelColor(left+whole,qRound(y*dpr)),edgeColor)<4,
        "fractional mixed coverage preserves the white part of the boundary pixel");

    HexCanvas tones;
    tones.resize(700,420);tones.setAddressSpace(0,4*4096-1);tones.setOverviewEnabled(true);
    QByteArray halfAscii(4096,'\xFF');std::fill(halfAscii.begin(),halfAscii.begin()+2048,'A');
    for(int page=0;page<4;++page) tones.deliverPage(page*4096,
        page==2 ? halfAscii : QByteArray(4096,page==0 ? '\0' : page==1 ? '\xFF' : 'A'),QByteArray(4096,'\1'),tones.sourceRevision());
    tones.show();drain();auto* tr=rail(tones);
    for(bool dark:{false,true}) {
        KswordTheme::SetDarkModeEnabled(dark);
        const auto image=capture(*tr);
        // Sample the binary half of the third page: a per-row summary must not
        // darken it just because the same page also contains readable text.
        const auto zeroColor=pixel(image,12,tr->height()/8),binary=pixel(image,12,tr->height()*3/8);
        const auto text=pixel(image,12,tr->height()*7/8),binaryWithinTextPage=pixel(image,12,tr->height()*23/32);
        const auto textWithinMixedPage=pixel(image,12,tr->height()*17/32);
        check(colorDistance(zeroColor,Qt::white)>0 && colorDistance(binary,Qt::white)>colorDistance(zeroColor,Qt::white),
            "zero and binary bytes have distinct light and deeper theme tints");
        check(colorDistance(text,Qt::white)>colorDistance(binary,Qt::white) && colorDistance(binaryWithinTextPage,binary)<4,
            "ASCII density is calculated for corresponding rows rather than the entire page");
        check(colorDistance(textWithinMixedPage,text)<4 && colorDistance(text,KswordTheme::PrimaryAccentColor())>20,
            "text rows deepen the tint without making it fully opaque");
        tones.grab().save(QCoreApplication::applicationDirPath()+(dark ? QStringLiteral("/overview-tones-dark.png") : QStringLiteral("/overview-tones-light.png")));
    }

    HexCanvas folded;
    constexpr std::uint64_t far=1ULL<<32;
    folded.resize(700,420);folded.setFoldUnknownRegions(true);folded.setOverviewEnabled(true);folded.setAddressSpace(0,far+8191);
    for(auto address:{0ULL,4096ULL,far,far+4096}) folded.deliverPage(address,QByteArray(4096,'\x41'),QByteArray(4096,'\1'),folded.sourceRevision());
    folded.setCaretAddress(far,false,false);folded.show();drain();auto* fr=rail(folded);capture(*fr);
    check(std::abs(fr->caretPosition()-(1.0+514.5/1026*(fr->height()-2)))<1,"folded overview follows 1026 projected rows rather than the 4GiB raw address span");
    const auto position=qRound(fr->caretPosition());
    QTest::mouseClick(fr,Qt::LeftButton,Qt::NoModifier,QPoint(5,position));drain();
    check(!folded.cellRect(far,HexCanvas::ActivePane::Hex).isNull(),"click, caret and viewport share the folded scale");

    HexCanvas evict;
    constexpr auto pageCount=ksword::memwb::HexViewport::kMaxCachedPages;
    evict.resize(500,600);evict.setOverviewEnabled(true);evict.setAddressSpace(0,(pageCount+2)*4096-1);
    evict.deliverPage(0,QByteArray(4096,'\x11'),QByteArray(4096,'\1'),evict.sourceRevision());evict.show();drain();
    evict.verticalScrollBar()->setValue(evict.verticalScrollBar()->maximum());auto* er=rail(evict);auto beforeEvict=capture(*er);
    check(pixel(beforeEvict,6,2)!=Qt::white,"cached first page contributes a read tint");
    for(std::uint64_t page=1;page<=pageCount;++page) evict.deliverPage(page*4096,QByteArray(4096,'\0'),QByteArray(4096,'\1'),evict.sourceRevision());
    auto afterEvict=capture(*er);
    if (evict.cellStateAt(0).byteState!=HexCanvas::ByteState::NotLoaded || pixel(afterEvict,6,2)!=Qt::white) {
        std::printf("EVICTION state=%d color=%s size=%dx%d builds=%llu first=%llu\n",
            static_cast<int>(evict.cellStateAt(0).byteState),pixel(afterEvict,6,2).name().toLatin1().constData(),er->width(),er->height(),
            static_cast<unsigned long long>(er->summaryBuildCount()),static_cast<unsigned long long>(evict.firstVisibleRow()));
        afterEvict.save(QCoreApplication::applicationDirPath()+QStringLiteral("/overview-eviction.png"));
    }
    check(evict.cellStateAt(0).byteState==HexCanvas::ByteState::NotLoaded && pixel(afterEvict,6,2)==Qt::white,
        "cache eviction restores unknown white rather than preserving a scan history");
    HexCanvas huge;
    huge.resize(500,420);huge.setAddressSpace(0,UINT64_MAX);huge.setOverviewEnabled(true);huge.show();drain();auto* hr=rail(huge);
    const int middle=hr->height()/2;
    QTest::mouseClick(hr,Qt::LeftButton,Qt::NoModifier,QPoint(5,middle));drain();
    check(huge.firstVisibleRow()>(1ULL<<58) && huge.firstVisibleRow()<(1ULL<<60)*3/4
        && std::abs(hr->viewportOutline().top()-middle)<3,"huge address-space clicks retain the original proportional scrollbar scale");
    QTest::mousePress(hr,Qt::LeftButton,Qt::NoModifier,hr->viewportOutline().center().toPoint());
    huge.setAddressSpace(0,8191);
    QTest::mouseMove(hr,QPoint(5,hr->height()-5));
    QTest::mouseRelease(hr,Qt::LeftButton,Qt::NoModifier,QPoint(5,hr->height()-5));drain();
    check(huge.firstVisibleRow()==0 && !huge.verticalScrollBar()->isSliderDown(),"source replacement cancels an overview drag without scrolling the new target");
    runFixedAddressUiTests();
    KswordTheme::SetDarkModeEnabled(oldDark);
}
