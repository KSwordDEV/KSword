// Native enumeration, occluded capture and scene interaction regressions.
// Decoration adapters below are intentionally not product visual acceptance.
#include "../Ksword5.1/Ksword5.1/UI/WindowTargetPicker.cpp"
#include <QEventLoop>
#include <QTest>
#include <iostream>
#include <stdexcept>
#include <cmath>

namespace ks::ui
{
    void StyleSecondaryWindow(QWidget*) {}
    void StyleSecondaryContentLayout(QLayout* layout) { layout->setContentsMargins(6, 6, 6, 6); }
    void StyleSecondaryButtonBox(QDialogButtonBox*) {}
    bool BindWidgetTheme(QWidget*, std::function<void()>, ThemePalettePolicy, bool) { return true; }
    void PrepareWidgetThemeBindingsForShow(QWidget*) {}
    void applyResponsiveWindowGeometry(QWidget* window, QWidget*, const QSize& size, const QSize& minimum, double)
    { window->setMinimumSize(minimum); window->resize(size); }
}

static int checks = 0;
static void require(bool condition, const char* message)
{
    ++checks;
    if (!condition) throw std::runtime_error(message);
}

template<class Request, class Result, class Worker>
static Result runJob(Request request, Worker worker)
{
    QObject owner;
    ks::ui::AsyncOperation operation(&owner);
    QEventLoop loop;
    Result result;
    bool done = false;
    operation.submit<Request, Result>(request, worker, [&](const Result& value, std::uint64_t) {
        result = value; done = true; loop.quit(); return true;
    }, [&](std::exception_ptr failure) {
        try { if (failure) std::rethrow_exception(failure); } catch (const std::exception& e) { std::cerr << "WORKER_ERROR=" << e.what() << std::endl; }
        loop.quit();
    });
    QTimer::singleShot(12000, &loop, &QEventLoop::quit);
    loop.exec();
    operation.close();
    require(done, "native worker completes and delivers through production AsyncOperation");
    return result;
}

static void paintWindow(QWidget& widget, const QColor& color)
{
    QPalette palette = widget.palette();
    palette.setColor(QPalette::Window, color);
    widget.setPalette(palette);
    widget.setAutoFillBackground(true);
    widget.repaint();
}

static void moveOver(QGraphicsView& view, const QPointF& scenePosition)
{
    // QWidget QTest::mouseMove uses the native cursor queue on Windows. Deliver
    // a local Qt event so the real scene hover dispatch also runs on the sandbox
    // desktop, which is separate from the physical input desktop.
    const QPoint position = view.mapFromScene(scenePosition);
    QMouseEvent move(QEvent::MouseMove, QPointF(position),
        QPointF(view.viewport()->mapToGlobal(position)), Qt::NoButton, Qt::NoButton, Qt::NoModifier);
    QCoreApplication::sendEvent(view.viewport(), &move);
}

int main(int argc, char** argv)
{
    ::SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
    QApplication app(argc, argv);
    app.setQuitOnLastWindowClosed(false);
    try
    {
        using namespace ks::ui;
        const PhysicalCoordinates coordinates;
        MONITORINFO monitor{};
        monitor.cbSize = sizeof(monitor);
        ::GetMonitorInfoW(::MonitorFromPoint(POINT{0, 0}, MONITOR_DEFAULTTOPRIMARY), &monitor);
        const QPoint origin(monitor.rcWork.left + 90, monitor.rcWork.top + 90);
        const QPoint probe = origin + QPoint(180, 140);
        QWidget back, front, hidden, minimized;
        for (QWidget* widget : {&back, &front, &hidden, &minimized})
        {
            widget->setAttribute(Qt::WA_ShowWithoutActivating);
            widget->setWindowTitle(QStringLiteral("KSword picker regression"));
            widget->resize(400, 260);
            (void)widget->winId();
            ::SetWindowPos(reinterpret_cast<HWND>(widget->winId()), HWND_TOPMOST,
                origin.x(), origin.y(), 400, 260, SWP_NOACTIVATE);
        }
        paintWindow(back, QColor(220, 30, 40));
        paintWindow(front, QColor(25, 80, 220));
        back.show(); front.show();
        minimized.show();
        ::ShowWindow(reinterpret_cast<HWND>(minimized.winId()), SW_SHOWMINNOACTIVE);
        ::SetWindowPos(reinterpret_cast<HWND>(front.winId()), HWND_TOPMOST,
            origin.x(), origin.y(), 400, 260, SWP_NOACTIVATE);
        QTest::qWait(100);
        const auto values = runJob<EnumerationRequest, std::vector<Candidate>>({probe, 0}, enumerate);
        const auto index = [&](WId hwnd) {
            for (std::size_t i = 0; i < values.size(); ++i) if (values[i].hwnd == static_cast<quintptr>(hwnd)) return i;
            return values.size();
        };
        require(index(front.winId()) < index(back.winId()) && index(back.winId()) < values.size(),
            "both fully overlapped top-level windows are present in real Z order");
        require(index(hidden.winId()) == values.size() && index(minimized.winId()) == values.size(),
            "hidden and minimized windows are excluded");
        const Candidate target = values[index(back.winId())];
        require(target.processName.compare(QStringLiteral("window_target_picker_tests.exe"), Qt::CaseInsensitive) == 0,
            "process metadata names the owning executable rather than the window title");
        require(!target.processIcon.isNull(), "process metadata contains owned executable icon pixels");
        const auto excluded = runJob<EnumerationRequest, std::vector<Candidate>>({probe, target.hwnd}, enumerate);
        require(std::none_of(excluded.begin(), excluded.end(), [&](const auto& v) { return v.hwnd == target.hwnd; }),
            "chooser HWND exclusion does not accidentally include its own window");
        // Unlike WGC, native geometry/enumeration work on the Codex sandbox
        // desktop. Test negative virtual coordinates without changing displays.
        ::SetWindowPos(reinterpret_cast<HWND>(back.winId()), HWND_TOPMOST,
            -700, -400, 400, 260, SWP_NOACTIVATE);
        const auto negative = runJob<EnumerationRequest, std::vector<Candidate>>({QPoint(-500, -260), 0}, enumerate);
        require(std::any_of(negative.begin(), negative.end(), [&](const auto& v) { return v.hwnd == target.hwnd; }),
            "negative native screen coordinates are not scaled or clamped");
        ::SetWindowPos(reinterpret_cast<HWND>(back.winId()), HWND_TOPMOST,
            origin.x(), origin.y(), 400, 260, SWP_NOACTIVATE);
        ::SetWindowPos(reinterpret_cast<HWND>(front.winId()), HWND_TOPMOST,
            origin.x(), origin.y(), 400, 260, SWP_NOACTIVATE);
        const HWND hit = ::WindowFromPoint(POINT{probe.x(), probe.y()});
        require(::GetAncestor(hit, GA_ROOT) == reinterpret_cast<HWND>(front.winId()),
            "native point resolves the front window at every Qt scale");
        wchar_t desktopName[256]{}, inputName[256]{};
        DWORD needed = 0;
        ::GetUserObjectInformationW(::GetThreadDesktop(::GetCurrentThreadId()), UOI_NAME,
            desktopName, sizeof(desktopName), &needed);
        const HDESK input = ::OpenInputDesktop(0, FALSE, DESKTOP_READOBJECTS);
        if (input)
        {
            ::GetUserObjectInformationW(input, UOI_NAME, inputName, sizeof(inputName), &needed);
            ::CloseDesktop(input);
        }
        const bool inputDesktop = inputName[0] && std::wcscmp(desktopName, inputName) == 0;
        Snapshot snapshot;
        if (inputDesktop)
        {
            snapshot = runJob<Candidate, Snapshot>(target, capture);
            require(snapshot.state == CaptureState::Ready && !snapshot.image.isNull(), "real WGC snapshot succeeds");
            const auto pixel = snapshot.image.pixelColor(snapshot.image.width() / 2, snapshot.image.height() / 2);
            require(pixel.red() > 160 && pixel.blue() < 100, "occluded red window captures its own pixels, not blue cover");
            paintWindow(back, QColor(25, 180, 80));
            require(snapshot.image.pixelColor(snapshot.image.width() / 2, snapshot.image.height() / 2) == pixel,
                "preview is an immutable static snapshot");
        }
        else
        {
            std::cout << "CAPTURE_SKIPPED=non-input desktop (WGC unavailable)\n";
            snapshot.image = QImage(400, 260, QImage::Format_RGB32);
            snapshot.image.fill(QColor(220, 30, 40));
            snapshot.state = CaptureState::Ready;
        }
        if (::SetWindowDisplayAffinity(reinterpret_cast<HWND>(back.winId()), WDA_EXCLUDEFROMCAPTURE))
        {
            const auto restricted = runJob<Candidate, Snapshot>(target, capture);
            require(restricted.state == CaptureState::Restricted && restricted.image.isNull(), "capture protection has an explicit state");
            ::SetWindowDisplayAffinity(reinterpret_cast<HWND>(back.winId()), WDA_NONE);
        }
        back.hide(); front.hide(); minimized.hide();
        PreviewScene scene;
        PreviewView view(nullptr);
        view.setScene(&scene);
        view.resize(1000, 500);
        view.show();
        int picked = 0;
        auto* lower = new PreviewItem;
        lower->setPos(layerPosition(1));
        lower->setZValue(-1);
        lower->candidate.title = QStringLiteral("lower");
        lower->snapshot = snapshot;
        lower->picked = [&] { picked = 2; };
        auto* upper = new PreviewItem;
        upper->candidate.title = QStringLiteral("upper");
        upper->snapshot = snapshot;
        upper->picked = [&] { picked = 1; };
        scene.addItem(lower); scene.addItem(upper);
        scene.setSceneRect(scene.itemsBoundingRect());
        QTest::qWait(30);
        require(planeProjection().map(QPointF(0, 0)).x() > planeProjection().map(QPointF(0, 440)).x(),
            "the upper screenshot edge leans right");
        const auto angle = [](const QTransform& transform) {
            return std::atan2(transform.m22(), -transform.m21()) * 180 / std::acos(-1.0);
        };
        require(std::abs(angle(planeProjection()) - 60) < .0001
            && std::abs(angle(planeProjection(true)) - 75) < .0001,
            "inspection changes the depth axis from 60 to 75 degrees");
        require(upper->sceneBoundingRect().left() == lower->sceneBoundingRect().left()
            && layerPosition(12).x() == 0, "all Z layers share the same horizontal alignment");
        require(upper->informationRect().left() > upper->previewRect().right()
            && !upper->informationRect().intersects(upper->previewRect()), "metadata occupies the right external column");
        const QPointF overlap(300, 100);
        require(scene.itemAt(overlap, QTransform()) == upper, "overlap hit testing follows visual Z order");
        const QPointF exposed(350, 205);
        require(scene.itemAt(exposed, QTransform()) == lower, "lower plane has an exposed selectable strip");
        moveOver(view, exposed);
        QTest::qWait(20);
        require(lower->highlighted() && !upper->highlighted(), "only the exposed lower window is highlighted");
        // A focused lower item must not keep its accent when the pointer moves
        // into an overlap and actually hits the upper item.
        lower->setFocus(Qt::TabFocusReason);
        moveOver(view, overlap);
        QTest::qWait(20);
        require(upper->highlighted() && !lower->highlighted(), "overlap hover has one highlight despite lower keyboard focus");
        moveOver(view, QPointF(5, 5));
        QTest::qWait(20);
        require(!upper->highlighted() && !lower->highlighted(), "leaving screenshots clears stale hover highlights");
        QTest::mouseClick(view.viewport(), Qt::LeftButton, Qt::NoModifier, view.mapFromScene(exposed));
        require(picked == 2, "left-click commits the visible lower window");
        const QPointF metadata = lower->mapToScene(lower->informationRect().center());
        require(scene.itemAt(metadata, QTransform()) == lower, "right-hand metadata hits its matching layer");
        view.ensureVisible(lower);
        moveOver(view, metadata);
        QTest::qWait(20);
        require(lower->highlighted() && !upper->highlighted(), "metadata hover highlights only the corresponding screenshot");
        lower->hide();
        QImage rendered(1200, 300, QImage::Format_ARGB32_Premultiplied);
        rendered.fill(Qt::transparent);
        {
            QPainter painter(&rendered);
            scene.render(&painter, QRectF(0, 0, 1200, 300), QRectF(0, 0, 1200, 300), Qt::IgnoreAspectRatio);
        }
        const QPoint middle = planeProjection().map(QPointF(340, 220)).toPoint();
        const QPoint bottom = planeProjection().map(QPointF(300, 400)).toPoint();
        require(rendered.pixelColor(middle).alpha() == 255,
            "ordinary screenshot is fully opaque");
        require(rendered.pixelColor(bottom).alpha() == 255,
            "the bottom of the screenshot remains fully opaque");
        const auto bounds = upper->boundingRect();
        scene.highlight(upper);
        require(upper->boundingRect() == bounds, "inspection does not resize the scene's layout bounds");
        const QPointF entryPoint = planeProjection().map(QPointF(660, 20));
        require(upper->contains(entryPoint), "75-degree inspection retains the original hover entry footprint");
        const QPointF tiltedPoint = planeProjection(true).map(QPointF(340, 420));
        require(upper->contains(tiltedPoint), "the extended inspected screenshot remains clickable");
        rendered.fill(Qt::transparent);
        {
            QPainter painter(&rendered);
            scene.render(&painter, QRectF(0, 0, 1200, 300), QRectF(0, 0, 1200, 300), Qt::IgnoreAspectRatio);
        }
        const QPoint inspected = planeProjection(true).map(QPointF(340, 220)).toPoint();
        require(rendered.pixelColor(inspected).alpha() == 255, "inspected screenshot is fully opaque");
        scene.highlight(nullptr);
        lower->show();
        WindowTargetPickerButton owner;
        owner.show();
        QPointer<Chooser> chooser = new Chooser(&owner, probe, [](quintptr) {});
        chooser->show();
        chooser->activateWindow();
        QTest::qWait(30);
        require(chooser, "chooser opens");
        require(chooser->windowType() == Qt::Window
            && chooser->windowFlags().testFlag(Qt::WindowMaximizeButtonHint)
            && chooser->windowFlags().testFlag(Qt::WindowMinimizeButtonHint),
            "chooser is a normal resizable window with minimize and maximize controls");
        auto* chooserView = chooser->findChild<QGraphicsView*>();
        QTest::keyClick(chooserView->viewport(), Qt::Key_F11);
        QTest::qWait(30);
        require(chooser && chooser->isFullScreen(), "F11 from the graphics viewport enters full screen");
        QTest::keyClick(chooserView->viewport(), Qt::Key_Escape);
        QTest::qWait(30);
        require(chooser && !chooser->isFullScreen() && chooser->isVisible(), "Escape leaves full screen without cancelling selection");
        chooser->showMaximized();
        QTest::qWait(30);
        require(chooser && chooser->isMaximized(), "native maximization settles before the next shortcut");
        QTest::keyClick(chooserView->viewport(), Qt::Key_F11);
        QTest::qWait(30);
        require(chooser && chooser->isFullScreen(), "a maximized chooser can enter full screen");
        QTest::keyClick(chooserView->viewport(), Qt::Key_F11);
        QTest::qWait(30);
        require(chooser && chooser->isMaximized(), "leaving full screen restores the previous maximized state");
        QTest::mouseClick(chooserView->viewport(), Qt::RightButton, Qt::NoModifier, QPoint(10, 10));
        QCoreApplication::sendPostedEvents(nullptr, QEvent::DeferredDelete);
        require(!chooser, "right-click cancels and destroys the chooser");
        int callbacks = 0;
        chooser = new Chooser(&owner, probe, [&](quintptr) { ++callbacks; });
        chooser->show();
        QTest::keyClick(chooser, Qt::Key_Escape);
        QCoreApplication::sendPostedEvents(nullptr, QEvent::DeferredDelete);
        require(!chooser && callbacks == 0, "Escape cancels without dispatching the old locate action");
        back.show();
        chooser = new Chooser(&owner, probe, [&](quintptr hwnd) {
            require(hwnd == target.hwnd, "selection delivers the chosen native HWND without another point hit test");
            ++callbacks;
        });
        chooser->show();
        QElapsedTimer timer;
        timer.start();
        PreviewItem* chosen = nullptr;
        while (chooser && !chosen && timer.elapsed() < 4000)
        {
            for (QGraphicsItem* item : chooser->findChild<QGraphicsView*>()->scene()->items())
                if (auto* preview = dynamic_cast<PreviewItem*>(item); preview && preview->candidate.hwnd == target.hwnd)
                    chosen = preview;
            if (!chosen) QTest::qWait(10);
        }
        require(chosen, "the original top-level window reaches the chooser scene");
        chosen->picked();
        QTest::qWait(20);
        QCoreApplication::sendPostedEvents(nullptr, QEvent::DeferredDelete);
        require(!chooser && callbacks == 1, "choosing a window closes first and dispatches exactly once");
        Candidate closed;
        const auto invalid = runJob<Candidate, Snapshot>(closed, capture);
        require(invalid.state == CaptureState::Closed && invalid.image.isNull(), "closed windows do not produce stale previews");
        QThreadPool::globalInstance()->waitForDone(3000);
        // The main program is still required for shared-layout visual acceptance.
        std::cout << "PICKER_CHECKS=" << checks << "\nOCCLUDED_CAPTURE=" << (inputDesktop ? "PASS" : "SKIPPED") << '\n';
        return 0;
    }
    catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
