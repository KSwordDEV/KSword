#include <Windows.h>
#include "control_inspection_provider_fixture.h"
#include "../Ksword5.1/Ksword5.1/OtherDock/WindowControlInspection.h"
#include "../Ksword5.1/Ksword5.1/OtherDock/WindowControlInspectionOverlay.h"
#include "../Ksword5.1/Ksword5.1/OtherDock/WindowListInteraction.h"
#include <QApplication>
#include <QCheckBox>
#include <QComboBox>
#include <QDialog>
#include <QImage>
#include <QPointer>
#include <QStyleFactory>
#include <QElapsedTimer>
#include <QLabel>
#include <QTabWidget>
#include <QTest>
#include <QTimer>
#include <QToolButton>
#include <QVBoxLayout>
#include <iostream>
#include <stdexcept>
#include <CommCtrl.h>

namespace ci = ks::control_inspection;
static int actions = 0, assertions = 0;
static HWND providerTarget = nullptr, providerButton = nullptr, providerEdit = nullptr;
static InspectionFixtureProvider* providerInstance = nullptr;
static void require(bool value, const char* message)
{ ++assertions; if (!value) throw std::runtime_error(message); }
static LRESULT CALLBACK targetProc(HWND window, UINT message, WPARAM wparam, LPARAM lparam)
{
    if (message == WM_GETOBJECT && static_cast<LONG>(lparam) == UiaRootObjectId
        && window == providerTarget && providerButton && providerEdit)
    {
        if (!providerInstance) providerInstance = new InspectionFixtureProvider(window, providerButton, providerEdit);
        return ::UiaReturnRawElementProvider(window, wparam, lparam, providerInstance);
    }
    if (message == WM_COMMAND && HIWORD(wparam) == BN_CLICKED) ++actions;
    return ::DefWindowProcW(window, message, wparam, lparam);
}
template<class Predicate> static bool waitFor(Predicate predicate, int limit = 8000)
{
    QElapsedTimer clock; clock.start();
    while (clock.elapsed() < limit) { if (predicate()) return true; QTest::qWait(20); }
    return predicate();
}
static QVector<ci::Node> scan(ci::Collector& collector, ci::Request request, int timeout = 8000)
{
    QVector<ci::Node> nodes;
    bool done = false;
    collector.scan(request);
    require(waitFor([&] {
        for (const auto& reply : collector.take()) {
            require(reply.generation == request.generation, "No replies from an obsolete generation");
            require(SUCCEEDED(reply.error), "Native/UIA scan completes without provider errors");
            nodes += reply.nodes; done = done || reply.done;
        }
        return done;
    }, timeout), "Collector completes a real window subtree");
    return nodes;
}
static void run()
{
    WNDCLASSW type{}; type.lpfnWndProc = targetProc; type.hInstance = ::GetModuleHandleW(nullptr);
    type.lpszClassName = L"KswordControlInspectionFixture";
    ::RegisterClassW(&type);
    HWND target = ::CreateWindowW(type.lpszClassName, L"Inspection fixture", WS_OVERLAPPEDWINDOW | WS_VISIBLE,
        70, 90, 500, 380, nullptr, nullptr, type.hInstance, nullptr);
    HWND button = ::CreateWindowW(L"BUTTON", L"Accept", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        20, 40, 100, 30, target, reinterpret_cast<HMENU>(1001), type.hInstance, nullptr);
    HWND edit = ::CreateWindowW(L"EDIT", L"Read only inspection", WS_CHILD | WS_VISIBLE | WS_BORDER,
        20, 90, 230, 26, target, reinterpret_cast<HMENU>(1002), type.hInstance, nullptr);
    HWND outsider = ::CreateWindowW(type.lpszClassName, L"Unrelated same process", WS_OVERLAPPEDWINDOW | WS_VISIBLE,
        1000, 90, 200, 150, nullptr, nullptr, type.hInstance, nullptr);
    HWND popup = ::CreateWindowExW(WS_EX_TOOLWINDOW, L"STATIC", L"Owned popup", WS_POPUP | WS_VISIBLE,
        100, 450, 130, 70, target, nullptr, type.hInstance, nullptr);
    require(target && button && edit && outsider && popup, "Create native controls and owned popup");
    providerTarget = target; providerButton = button; providerEdit = edit;
    require(ci::belongs(button, target, nullptr), "Child belongs to target");
    require(ci::belongs(popup, target, nullptr), "Owned popup belongs to target");
    require(!ci::belongs(outsider, target, nullptr), "Same PID alone does not admit another window");
    require(!ci::belongs(button, target, target), "Inspector exclusion covers descendants");
    require(ci::relatedRoots(target, nullptr).contains(popup), "Related popup added as another root");

    ci::PickGate gate;
    const auto click = [&](bool scope) {
        bool complete = false;
        const bool down = gate.mouse(WM_LBUTTONDOWN, QPoint(12, 34), scope, complete);
        const bool up = gate.mouse(WM_LBUTTONUP, QPoint(55, 66), false, complete);
        require(down == up, "Press/release delivered as a pair even if release leaves the target");
        if (!down) ::SendMessageW(button, BM_CLICK, 0, 0);
        return complete;
    };
    require(!click(true) && actions == 1, "Ordinary click executes target action");
    gate.armed = true;
    require(click(true) && actions == 1 && !gate.armed, "One-shot pick does not execute target action");
    require(gate.pressed == QPoint(12, 34), "Picking retains press location, not release location");
    require(!click(true) && actions == 2, "Next click automatically executes target action");
    gate.armed = true;
    require(!click(false) && gate.armed && actions == 3, "Click outside target is untouched");
    bool completed = false;
    require(gate.mouse(WM_LBUTTONDOWN, {}, true, completed), "Start paired interception");
    gate.cancel();
    require(gate.mouse(WM_LBUTTONUP, {}, false, completed) && !completed,
        "Pause/close cancellation still consumes paired release without selecting");
    gate.armed = true; gate.cancel();
    require(!click(true) && actions == 4, "Cancelling before press restores ordinary input");

    ci::Collector collector;
    ci::Request request; request.generation = 1; request.root = target; request.view = ci::View::Native;
    auto nodes = scan(collector, request);
    require(nodes.size() == 4, "Native tree includes root, button, edit and associated popup");
    ci::Node buttonNode, editNode;
    for (const auto& node : nodes) {
        if (node.window == button) buttonNode = node;
        if (node.window == edit) editNode = node;
    }
    require(buttonNode.parent == ci::nativeKey(target), "Native tree preserves actual parent");
    require(buttonNode.bounds == ci::physicalBounds(button), "Native bounds are physical screen pixels");
    require(buttonNode.properties.value("ControlId") == "1001", "Win32 control ID exposed");
    collector.details(request, buttonNode.id, 50);
    require(waitFor([&] {
        for (const auto& reply : collector.take()) if (reply.fromTree)
            return reply.serial == 50 && reply.hit.name == "Accept";
        return false;
    }), "Tree properties are read on the worker, without requiring an on-screen hover");
    ::ShowWindow(edit, SW_HIDE);
    ++request.generation; nodes = scan(collector, request);
    bool hidden = false;
    for (const auto& node : nodes) if (node.window == edit) hidden = node.offscreen;
    require(hidden, "Hidden controls remain in tree with offscreen state");
    ::ShowWindow(edit, SW_SHOWNA);

    request.view = ci::View::Controls; ++request.generation;
    auto automation = scan(collector, request);
    for (const auto& node : automation) std::cout << "UIA_NODE=" << node.name.toStdString()
        << " TYPE=" << node.type.toStdString() << " ID=" << node.id.toStdString() << '\n';
    std::cout << "PROVIDER_CHILD_NAVIGATIONS=" << InspectionFixtureProvider::childNavigations
        << " CHILD_PROPERTIES=" << InspectionFixtureProvider::propertiesRead << '\n';
    require(automation.size() >= 1, "Explicit HWND UIA lookup obtains the private-desktop root");
    bool namedButton = false;
    for (const auto& node : automation) if (node.name == "Accept") namedButton = !node.id.isEmpty();
    request.view = ci::View::Raw; ++request.generation;
    auto raw = scan(collector, request);
    for (const auto& node : raw) std::cout << "RAW_NODE=" << node.name.toStdString() << " TYPE=" << node.type.toStdString() << '\n';
    require(raw.size() >= automation.size(), "Raw view retains at least the control-view elements");
    std::cout << "UIA_NATIVE_BUTTON_AVAILABLE=" << namedButton << '\n';
    request.view = ci::View::Native; ++request.generation; scan(collector, request);
    const QPoint center = ci::physicalBounds(button).center();
    collector.hit(request, center, 99, true);
    require(waitFor([&] {
        for (const auto& reply : collector.take()) if (reply.hover)
            return reply.picked && reply.serial == 99 && reply.hit.window == button;
        return false;
    }), "Real physical hit-test obtains the picked native control");
    collector.hit(request, center, 100, false); collector.cancel();
    QTest::qWait(80); require(collector.take().isEmpty(), "Cancellation suppresses obsolete hover replies");
    {
        QVector<HWND> many;
        for (int index = 0; index < 1000; ++index)
            many.push_back(::CreateWindowW(L"STATIC", L"Bulk control", WS_CHILD,
                0, 0, 1, 1, target, nullptr, type.hInstance, nullptr));
        int ticks = 0; QTimer heartbeat; heartbeat.setInterval(1);
        QObject::connect(&heartbeat, &QTimer::timeout, [&] { ++ticks; }); heartbeat.start();
        ++request.generation;
        // Same-process GetWindowText synchronously enters the fixture's UI
        // thread; this private-desktop message-pump test is slower than the
        // cross-process shared-caption path used by normal targets.
        const auto bulk = scan(collector, request, 45000);
        require(bulk.size() == 1004, "Large native subtree completes all nodes without truncation");
        require(ticks > 0, "UI event loop remains responsive during large-tree collection");
        for (HWND window : many) ::DestroyWindow(window);
    }

    QDialog detail;
    detail.setAttribute(Qt::WA_ShowWithoutActivating); detail.resize(900, 650);
    detail.move(650, 300);
    auto* layout = new QVBoxLayout(&detail); auto* tabs = new QTabWidget(&detail); layout->addWidget(tabs);
    tabs->addTab(new QWidget(tabs), "Other");
    DWORD pid = 0; const DWORD tid = ::GetWindowThreadProcessId(target, &pid);
    auto* page = ci::CreatePage(target, pid, tid, 0, tabs); tabs->addTab(page, "Inspection");
    detail.show();
    require(!detail.findChild<QWidget*>("ks_control_overlay"), "Loading an unvisited tab does not start inspection");
    tabs->setCurrentWidget(page);
    auto* view = page->findChild<QComboBox*>("ks_control_view"); view->setCurrentIndex(2);
    auto* tree = page->findChild<QTreeWidget*>("ks_control_tree");
    require(waitFor([&] { return tree->topLevelItemCount() && tree->topLevelItem(0)->childCount() >= 3; }),
        "First visit automatically scans and renders native subtree including popup");
    QWidget* overlay = detail.findChild<QWidget*>("ks_control_overlay");
    require(overlay && overlay->isVisible(), "First visit automatically shows overlay");
    const LONG_PTR styles = ::GetWindowLongPtrW(reinterpret_cast<HWND>(overlay->winId()), GWL_EXSTYLE);
    require((styles & WS_EX_LAYERED) && (styles & WS_EX_TRANSPARENT) && (styles & WS_EX_NOACTIVATE),
        "Overlay is layered, input-transparent and non-activating");
    {
        ci::ClipOverlay(overlay, target, reinterpret_cast<HWND>(detail.winId()));
        ci::UpdateOverlay(overlay, {buttonNode}, {}, {}, true, false, {});
        const QPoint offset = ci::physicalBounds(reinterpret_cast<HWND>(overlay->winId())).topLeft();
        const QPoint inside = buttonNode.bounds.center() - offset;
        const auto ordinary = overlay->grab().toImage();
        require(ordinary.rect().contains(inside) && ordinary.pixelColor(inside).alpha() == 0,
            "Ordinary controls have no fill, preventing nested-container tint accumulation");
        const QPoint innerBorder(buttonNode.bounds.left() + 1 - offset.x(), inside.y());
        require(ordinary.pixelColor(innerBorder).alpha() >= 160,
            "Ordinary outline remains visible one physical pixel inside the edge");
        ci::UpdateOverlay(overlay, {buttonNode}, buttonNode, {}, true, false, {});
        const auto hovered = overlay->grab().toImage();
        require(hovered.pixelColor(inside).alpha() >= 15 && hovered.pixelColor(inside).alpha() <= 40,
            "Hovered control has a faint independent fill");
        const QPalette originalPalette = overlay->palette();
        QPalette transparentPalette = originalPalette;
        transparentPalette.setColor(QPalette::Base, Qt::transparent);
        overlay->setPalette(transparentPalette);
        ci::UpdateOverlay(overlay, {buttonNode}, buttonNode, {}, true, true, buttonNode.bounds.center());
        const auto card = overlay->grab().toImage();
        const qreal scale = overlay->devicePixelRatioF();
        const QPoint backgroundProbe = inside + QPoint(qRound(24 * scale), qRound(28 * scale));
        require(card.rect().contains(backgroundProbe) && card.pixelColor(backgroundProbe).alpha() == 255,
            "Hover card stays opaque when the application's Base palette is transparent");
        require(card.copy(QRect(inside + QPoint(qRound(12 * scale), qRound(16 * scale)),
            QSize(qRound(400 * scale), qRound(150 * scale))).intersected(card.rect()))
                .save(".codex-build-logs/control-inspection-tests/hover-card.png"), "Save readable hover-card preview");
        overlay->setPalette(originalPalette);
        ci::UpdateOverlay(overlay, {buttonNode}, buttonNode, {}, true, false, {});
        HWND occluder = ::CreateWindowExW(WS_EX_NOACTIVATE | WS_EX_TOOLWINDOW, L"STATIC", L"Occluder",
            WS_POPUP | WS_VISIBLE, buttonNode.bounds.center().x() - 10, buttonNode.bounds.center().y() - 10,
            20, 20, nullptr, nullptr, type.hInstance, nullptr);
        ::SetWindowPos(occluder, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
        ci::ClipOverlay(overlay, target, reinterpret_cast<HWND>(detail.winId()));
        const auto clipped = overlay->grab().toImage();
        require(clipped.pixelColor(inside).alpha() == 0, "Overlay does not paint on an unrelated occluding window");
        ::DestroyWindow(occluder);
    }
    auto* child = tree->topLevelItem(0)->child(0); tree->setCurrentItem(child);
    const QString selected = child->data(0, Qt::UserRole).toString();
    auto* origin = page->findChild<QLabel*>("ks_control_property_origin");
    require(origin->text().contains(QString::fromUtf8("树节点选择")), "Tree selection sets property origin");
    auto* refresh = page->findChild<QToolButton*>("ks_control_refresh"); refresh->click();
    require(waitFor([&] { return tree->currentItem() && tree->currentItem()->data(0, Qt::UserRole).toString() == selected; }),
        "Refresh retains stable tree selection");
    tabs->setCurrentIndex(0); QTest::qWait(80);
    require(overlay->isVisible(), "Switching tabs does not end inspection");
    tabs->setCurrentWidget(page);
    auto* pause = page->findChild<QToolButton*>("ks_control_pause"); pause->click();
    require(!overlay->isVisible() && tree->currentItem(), "Pause hides overlay while preserving browsable tree");
    pause->click(); require(waitFor([&] { return overlay->isVisible(); }), "Resume restores ordinary observation");
    require(page->findChild<QCheckBox*>("", Qt::FindDirectChildrenOnly) != nullptr, "Display options exposed");
    require(detail.grab().save(".codex-build-logs/control-inspection-tests/page.png"), "Save actual page preview");
    {
        QPalette dark = detail.palette();
        dark.setColor(QPalette::Window, QColor(18, 24, 32)); dark.setColor(QPalette::Base, QColor(22, 29, 38));
        dark.setColor(QPalette::WindowText, Qt::white); dark.setColor(QPalette::Text, Qt::white);
        dark.setColor(QPalette::Button, QColor(28, 38, 48)); dark.setColor(QPalette::ButtonText, Qt::white);
        dark.setColor(QPalette::Highlight, QColor(0, 190, 140)); dark.setColor(QPalette::HighlightedText, Qt::black);
        qApp->setPalette(dark); detail.setPalette(dark); page->setPalette(dark); QTest::qWait(60);
        require(overlay->palette().color(QPalette::Active, QPalette::Highlight) == dark.color(QPalette::Active, QPalette::Highlight),
            "Existing overlay follows a live theme-accent change");
        require(detail.grab().save(".codex-build-logs/control-inspection-tests/page-dark.png"), "Save dark page preview");
    }
    {
        QDialog second; auto* secondLayout = new QVBoxLayout(&second);
        auto* another = ci::CreatePage(target, pid, tid, 0, &second); secondLayout->addWidget(another);
        second.setAttribute(Qt::WA_ShowWithoutActivating); second.show();
        require(waitFor([&] { return pause->isChecked() && !overlay->isVisible(); }),
            "Starting another inspector pauses the original session");
        second.close();
    }
    pause->click(); require(waitFor([&] { return overlay->isVisible(); }), "Original inspector can resume after another closes");
    detail.showMinimized(); require(waitFor([&] { return !overlay->isVisible(); }), "Minimization suspends overlay");
    detail.showNormal(); require(waitFor([&] { return overlay->isVisible(); }), "Restore resumes overlay");
    ::DestroyWindow(target);
    require(waitFor([&] { return !overlay->isVisible() && !pause->isEnabled(); }), "Destroyed target ends inspection");
    detail.close(); ::DestroyWindow(outsider);
    if (providerInstance) { providerInstance->Release(); providerInstance = nullptr; }
}
int main(int argc, char** argv)
{
    if (argc > 1 && std::string(argv[1]) == "--uia-smoke")
    {
        QApplication app(argc, argv);
        try {
            WNDCLASSW type{}; type.lpfnWndProc = targetProc; type.hInstance = ::GetModuleHandleW(nullptr);
            type.lpszClassName = L"KswordControlInspectionOffscreenFixture"; ::RegisterClassW(&type);
            providerTarget = ::CreateWindowExW(WS_EX_NOACTIVATE | WS_EX_TOOLWINDOW, type.lpszClassName,
                L"Inspection fixture", WS_POPUP, -16000, -16000, 500, 380, nullptr, nullptr, type.hInstance, nullptr);
            providerButton = ::CreateWindowW(L"BUTTON", L"Accept", WS_CHILD | WS_VISIBLE,
                20, 40, 100, 30, providerTarget, reinterpret_cast<HMENU>(1001), type.hInstance, nullptr);
            providerEdit = ::CreateWindowW(L"EDIT", L"Read only inspection", WS_CHILD | WS_VISIBLE,
                20, 90, 230, 26, providerTarget, reinterpret_cast<HMENU>(1002), type.hInstance, nullptr);
            ::ShowWindow(providerTarget, SW_SHOWNOACTIVATE);
            ci::Collector collector; ci::Request request; request.generation = 1; request.root = providerTarget;
            auto nodes = scan(collector, request);
            bool button = false, edit = false;
            for (const auto& node : nodes) {
                std::cout << "UIA_DEFAULT_NODE=" << node.name.toStdString() << " ID=" << node.id.toStdString() << '\n';
                if (node.name == "Accept") button = !node.id.isEmpty();
                if (node.name == "Read only inspection") edit = !node.id.isEmpty();
            }
            require(button && edit, "Active-desktop UIA enumerates non-HWND logical controls");
            ++request.generation; request.view = ci::View::Raw;
            require(scan(collector, request).size() >= nodes.size(), "Active-desktop raw tree covers logical controls");
            collector.cancel(); ::DestroyWindow(providerTarget);
            std::cout << "UIA_ACTIVE_DESKTOP_TESTS=SUCCESS\n"; return 0;
        } catch (const std::exception& error) { std::cerr << "UIA_ACTIVE_DESKTOP_TESTS=FAILURE: " << error.what() << '\n'; return 1; }
    }
    const HDESK original = ::GetThreadDesktop(::GetCurrentThreadId());
    const std::wstring name = L"KswordControlInspectionTests-" + std::to_wstring(::GetCurrentProcessId());
    HDESK desktop = ::CreateDesktopW(name.c_str(), nullptr, nullptr, 0, GENERIC_ALL, nullptr);
    if (!desktop || !::SetThreadDesktop(desktop)) return 2;
    int result = 0;
    {
        QApplication app(argc, argv);
        app.setStyle(QStyleFactory::create("Fusion"));
        try { run(); std::cout << "CONTROL_INSPECTION_TESTS=SUCCESS ASSERTIONS=" << assertions << '\n'; }
        catch (const std::exception& error) { std::cerr << "CONTROL_INSPECTION_TESTS=FAILURE: " << error.what() << '\n'; result = 1; }
    }
    ::SetThreadDesktop(original); ::CloseDesktop(desktop); return result;
}
