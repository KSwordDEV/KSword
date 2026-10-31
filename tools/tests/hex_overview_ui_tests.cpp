#include "HexCanvas.h"
#include "HexCanvasOverviewBar.h"
#include <QApplication>
#include <QCoreApplication>
#include <QScrollBar>
#include <QStyleOptionSlider>
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
    check(r && r->isVisible() && r->width()==Rail::kWidth,"overview rail is visible and narrow");
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
        check(colorDistance(nonzero,KswordTheme::PrimaryAccentColor())<4,"all nonzero read bytes use maximum theme opacity");
        check(colorDistance(nonzero,base)>colorDistance(zero,base),"nonzero content increases opacity");
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
    check(colorDistance(pixel(mixedImage,2,y),KswordTheme::PrimaryAccentColor())<4 && pixel(mixedImage,7,y)==Qt::white,
        "mixed bin preserves half unknown white and computes nonzero opacity from read bytes alone");
    data.fill('\0');mixed.deliverPage(0,data,valid,mixed.sourceRevision());mixedImage=capture(*mr);
    check(pixel(mixedImage,2,y)!=Qt::white && pixel(mixedImage,7,y)==Qt::white,"mixed real-zero bin keeps its unknown half white");
    data.fill('\x42');valid.fill('\0');std::fill(valid.begin(),valid.begin()+3,'\1');
    mixed.deliverPage(0,data,valid,mixed.sourceRevision());mixedImage=capture(*mr);
    const auto dpr=mixedImage.devicePixelRatio();
    const int left=qRound(mr->stripRect().left()*dpr),right=qRound(mr->stripRect().right()*dpr);
    const double coverage=(right-left)*3.0/16;
    const int whole=static_cast<int>(coverage);
    const auto edgeColor=KswordTheme::BlendColors(Qt::white,KswordTheme::PrimaryAccentColor(),qRound((coverage-whole)*255));
    check(colorDistance(mixedImage.pixelColor(left+whole,qRound(y*dpr)),edgeColor)<4,
        "fractional mixed coverage preserves the white part of the boundary pixel");

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
    KswordTheme::SetDarkModeEnabled(oldDark);
}
