#include <QApplication>
#include <QMouseEvent>
#include <QPainter>
#include <QStyleOption>
#include <QStyle>
#include <QTabBar>
#include <QImage>
#include <QPushButton>
#include <QSpinBox>
#include "MonitorDock/WinAPIParameterDecode.h"
#include "UI/FlowLayout.h"
#include <algorithm>
#include <functional>
#include <iostream>
namespace KswordTheme {
    QColor SurfaceAltColor() { return QColor(210, 220, 230); }
    QColor SurfaceMutedColor() { return QColor(160, 170, 180); }
    QColor EnsureTextContrast(const QColor& color, const QColor&, double = 4.5) { return color; }
}
using namespace ks::monitor;
class WinAPIParameterEditor {
public:
    ks::ui::FlowLayout* m_typeActions = nullptr;
    QSpinBox* m_byteCount = nullptr;
    int m_orderedSlotWidth = 0, m_orderedByteCount = 0;
    void reorderTypeButtons(int slotWidth);
};
// PRODUCTION_SORT
// PRODUCTION_BAR
#define CHECK(x) do { if (!(x)) { std::cerr << "FAIL " << __LINE__ << ": " #x "\n"; return 1; } } while (false)
static QImage render(QWidget& widget) {
    QImage image(widget.size(), QImage::Format_ARGB32_Premultiplied); image.fill(Qt::transparent); widget.render(&image); return image;
}
int main(int argc, char** argv) {
    QApplication app(argc, argv); AllocationTabBar bar;
    bar.setMovable(true); bar.setExpanding(false); bar.setUsesScrollButtons(false); bar.setMouseTracking(true);
    bar.addTab(QStringLiteral("char")); bar.addTab(QStringLiteral("int")); bar.setTabData(0, 40); bar.setTabData(1, 160);
    bar.setFixedSize(200, 36); bar.show(); app.processEvents();
    CHECK(bar.tabRect(0).width() == 40 && bar.tabRect(1).width() == 160);
    const auto normal = render(bar); CHECK(normal.pixelColor(20, 4) == normal.pixelColor(80, 4));
    const QPointF hover(20, 15); QMouseEvent move(QEvent::MouseMove, hover, Qt::NoButton, Qt::NoButton, Qt::NoModifier);
    QApplication::sendEvent(&bar, &move); const auto hovered = render(bar);
    CHECK(hovered.pixelColor(20, 4) != normal.pixelColor(20, 4));
    int removed = -1; bar.removeClicked = [&](int index) { removed = index; };
    QMouseEvent press(QEvent::MouseButtonPress, hover, bar.mapToGlobal(hover.toPoint()), Qt::LeftButton, Qt::LeftButton, Qt::NoModifier);
    QMouseEvent release(QEvent::MouseButtonRelease, hover, bar.mapToGlobal(hover.toPoint()), Qt::LeftButton, Qt::NoButton, Qt::NoModifier);
    QApplication::sendEvent(&bar, &press); QApplication::sendEvent(&bar, &release); CHECK(removed == 0);
    removed = -1; int dragFinished = 0; bar.dragFinished = [&]() { ++dragFinished; };
    QApplication::sendEvent(&bar, &press);
    QMouseEvent startDrag(QEvent::MouseMove, QPointF(50, 15), bar.mapToGlobal(QPoint(50, 15)), Qt::NoButton, Qt::LeftButton, Qt::NoModifier);
    QApplication::sendEvent(&bar, &startDrag);
    QMouseEvent drag(QEvent::MouseMove, QPointF(170, 15), bar.mapToGlobal(QPoint(170, 15)), Qt::NoButton, Qt::LeftButton, Qt::NoModifier);
    QApplication::sendEvent(&bar, &drag);
    QMouseEvent dragRelease(QEvent::MouseButtonRelease, QPointF(170, 15), bar.mapToGlobal(QPoint(170, 15)), Qt::LeftButton, Qt::NoButton, Qt::NoModifier);
    QApplication::sendEvent(&bar, &dragRelease); CHECK(removed == -1 && dragFinished == 1);
    CHECK(bar.tabText(1) == QStringLiteral("char"));
    AllocationTabBar aligned; aligned.setExpanding(false); aligned.setUsesScrollButtons(false);
    auto palette = aligned.palette(); palette.setColor(QPalette::Window, QColor(20, 30, 40)); palette.setColor(QPalette::Button, QColor(210, 220, 230));
    aligned.setPalette(palette); aligned.setAutoFillBackground(true);
    aligned.addTab(QStringLiteral("char")); aligned.addTab(QStringLiteral("int"));
    aligned.setTabData(0, QVariantList{320, 40}); aligned.setTabData(1, QVariantList{320, 160});
    aligned.setFixedSize(640, 36); aligned.show(); app.processEvents();
    const auto alignment = render(aligned);
    CHECK(alignment.pixelColor(20, 4) == alignment.pixelColor(100, 4));
    CHECK(alignment.pixelColor(400, 4) == alignment.pixelColor(520, 4));
    CHECK(alignment.pixelColor(318, 4) != alignment.pixelColor(300, 4));
    aligned.setTabData(0, 120); aligned.setTabData(1, 240);
    aligned.setFixedWidth(0); aligned.setFixedWidth(360); app.processEvents();
    CHECK(aligned.tabRect(0).width() == 120 && aligned.tabRect(1).width() == 240);
    const auto resized = render(aligned);
    CHECK(resized.pixelColor(118, 4) != resized.pixelColor(100, 4));
    QWidget owner; ks::ui::FlowLayout flow(&owner, 0, 8, 8); QSpinBox bytes(&owner); bytes.setRange(1, 1024); bytes.setValue(48); bytes.setProperty("ks_type_role", -1);
    WinAPIParameterEditor editor; editor.m_typeActions = &flow; editor.m_byteCount = &bytes;
    QPushButton pointer(&owner), large(&owner), small(&owner), array(&owner);
    pointer.setProperty("ks_type_id", int(RawParameterType::Pointer)); large.setProperty("ks_type_id", int(RawParameterType::LongLong));
    small.setProperty("ks_type_id", int(RawParameterType::Char)); array.setProperty("ks_type_id", int(RawParameterType::Bytes));
    flow.addWidget(&large); flow.addWidget(&pointer); flow.addWidget(&small); flow.addWidget(&array); flow.addWidget(&bytes);
    editor.reorderTypeButtons(4);
    CHECK(flow.itemAt(0)->widget() == &bytes && flow.itemAt(1)->widget() == &small && flow.itemAt(2)->widget() == &array && flow.itemAt(3)->widget() == &pointer && flow.itemAt(4)->widget() == &large);
    editor.reorderTypeButtons(8);
    CHECK(flow.itemAt(0)->widget() == &bytes && flow.itemAt(1)->widget() == &small && flow.itemAt(2)->widget() == &array && flow.itemAt(3)->widget() == &pointer && flow.itemAt(4)->widget() == &large);
    bytes.setValue(1); editor.reorderTypeButtons(8);
    CHECK(flow.itemAt(0)->widget() == &bytes && flow.itemAt(1)->widget() == &small && flow.itemAt(2)->widget() == &array);
    std::cout << "PASS: proportional tab widths, neutral selection, hover, click and drag separation\n";
}
