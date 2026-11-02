// Natural first Paint versus settled layout. Production lifecycle/layout bodies
// are extracted unchanged by test_detail_layout_first_frame.py; business editor
// contents and row expansion are adapters outside this timing test's scope.
#include "DetailLayoutHost.h"
#include <QAbstractItemView>
#include <QApplication>
#include <QEvent>
#include <QEventLoop>
#include <QLabel>
#include <QPointer>
#include <QSplitter>
#include <QTableWidget>
#include <QTimer>
#include <QToolButton>
#include <QVBoxLayout>
#include <cstdio>
#include <functional>
#include <memory>

namespace {
using ks::settings::DetailDisplayScheme;
int checks = 0, failures = 0, cases = 0;
QString caseName;
void check(bool ok, const char* label)
{
    ++checks;
    if (!ok) { ++failures; std::fprintf(stderr, "FAIL [%s] %s\n", qPrintable(caseName), label); }
}
void settle()
{
    QEventLoop loop;
    QTimer::singleShot(20, &loop, &QEventLoop::quit);
    loop.exec();
}
QString rectangle(const QWidget* widget)
{
    if (!widget) return QStringLiteral("null");
    const QRect r = widget->geometry();
    return QStringLiteral("%1,%2,%3,%4,hidden=%5").arg(r.x()).arg(r.y()).arg(r.width()).arg(r.height()).arg(widget->isHidden());
}
class OwnerWidget : public QWidget {
public:
    int showsToParent = 0;
protected:
    bool event(QEvent* value) override
    {
        if (value->type() == QEvent::ShowToParent) ++showsToParent;
        return QWidget::event(value);
    }
};
struct Fixture {
    std::unique_ptr<QWidget> outer;
    OwnerWidget owner;
    QVBoxLayout root{&owner};
    QPointer<QSplitter> splitter;
    QPointer<QWidget> mainPane, detailPane;
    QPointer<QTableWidget> table;
    QPointer<CodeEditorWidget> editor;
    QPointer<ks::ui::DetailLayoutHost> host;
    QString snapshot() const
    {
        QSplitter* actual = splitter.data();
        if (!actual && table)
            for (QWidget* p = table->parentWidget(); p; p = p->parentWidget())
                if ((actual = qobject_cast<QSplitter*>(p))) break;
        QString result = QStringLiteral("bound=%1;scheme=%2;split=%3,%4;%5;main=%6;detail=%7")
            .arg(host && host->isBound()).arg(host ? int(host->effectiveScheme()) : -1)
            .arg(actual ? actual->count() : -1).arg(actual ? int(actual->orientation()) : -1)
            .arg(rectangle(actual), rectangle(mainPane), rectangle(detailPane));
        if (actual)
            for (int i = 0; i < actual->count(); ++i)
                result += QStringLiteral(";child%1=%2").arg(i).arg(rectangle(actual->widget(i)));
        return result;
    }
    explicit Fixture(bool embedded = false)
    {
        owner.resize(800, 560);
        if (embedded) {
            outer = std::make_unique<QWidget>();
            outer->resize(800, 560);
            auto* layout = new QVBoxLayout(outer.get());
            layout->setContentsMargins(0, 0, 0, 0);
            layout->addWidget(&owner);
        }
        root.setContentsMargins(6, 6, 6, 6);
        root.setSpacing(8);
    }
    void showOwner() { if (outer) outer->show(); else owner.show(); }
    void panels(bool inSplitter, bool mount)
    {
        if (inSplitter) {
            splitter = new QSplitter(Qt::Vertical, &owner);
            root.addWidget(splitter);
        }
        mainPane = new QWidget(&owner);
        detailPane = new QWidget(&owner);
        auto* left = new QVBoxLayout(mainPane);
        auto* right = new QVBoxLayout(detailPane);
        table = new QTableWidget(3, 2, mainPane);
        table->setItem(0, 0, new QTableWidgetItem(QStringLiteral("fixture")));
        editor = new CodeEditorWidget(detailPane);
        editor->setMinimumHeight(70);
        left->addWidget(table);
        right->addWidget(editor);
        if (mount) mountPanels();
    }
    void mountPanels()
    {
        if (splitter) { splitter->addWidget(mainPane); splitter->addWidget(detailPane); }
        else { root.addWidget(mainPane); root.addWidget(detailPane); }
    }
    void createHost(bool explicitBinding)
    {
        if (explicitBinding)
            host = new ks::ui::DetailLayoutHost(table, editor, &owner, {splitter, mainPane, detailPane});
        else host = new ks::ui::DetailLayoutHost(table, editor, &owner);
    }
};
class PaintObserver : public QObject {
public:
    Fixture* fixture = nullptr;
    bool armed = false;
    QString first;
    int paints = 0;
protected:
    bool eventFilter(QObject* target, QEvent* event) override
    {
        if (!armed || event->type() != QEvent::Paint) return false;
        auto* widget = qobject_cast<QWidget*>(target);
        if (!widget || (widget != &fixture->owner && !fixture->owner.isAncestorOf(widget))) return false;
        if (first.isEmpty()) first = fixture->snapshot();
        ++paints;
        return false;
    }
};
class BoundaryAction : public QObject {
public:
    std::function<void()> action;
    std::function<bool()> ready;
    QEvent::Type trigger = QEvent::Hide;
    bool called = false;
protected:
    bool eventFilter(QObject*, QEvent* event) override
    {
        if (!called && event->type() == trigger && (!ready || ready())) {
            called = true;
            action();
        }
        return false;
    }
};
void exercise(bool explicitBinding, bool existingSplitter, bool visibleOwner,
    bool mountAfterCtor, int backlog, DetailDisplayScheme scheme,
    bool keepHidden = false, bool embeddedOwner = false)
{
    ++cases;
    caseName = QStringLiteral("%1-%2-%3-%4-queue%5-scheme%6")
        .arg(explicitBinding ? "explicit" : "compat", existingSplitter ? "split" : "box",
             visibleOwner ? "dynamic" : "hidden", mountAfterCtor ? "late-panels" : "ready")
        .arg(backlog).arg(int(scheme));
    if (keepHidden) caseName += QStringLiteral("-explicitly-hidden");
    if (embeddedOwner) caseName += QStringLiteral("-embedded-owner");
    Fixture fixture(embeddedOwner);
    PaintObserver observer;
    observer.fixture = &fixture;
    qApp->installEventFilter(&observer);
    if (visibleOwner) { fixture.showOwner(); settle(); fixture.owner.update(); }
    for (int i = 0; i < backlog; ++i)
        QTimer::singleShot(0, &fixture.owner, [&fixture] { fixture.owner.update(); });
    fixture.panels(existingSplitter, !mountAfterCtor);
    if (keepHidden) fixture.splitter->hide();
    fixture.createHost(explicitBinding);
    check(fixture.owner.findChildren<QToolButton*>().isEmpty(),
        "constructor synchronously created host UI before page construction completed");
    fixture.host->applyScheme(scheme);
    if (mountAfterCtor) fixture.mountPanels();
    observer.armed = true;
    if (!visibleOwner) fixture.showOwner();
    else {
        if (fixture.splitter) { if (!keepHidden) fixture.splitter->show(); }
        else { fixture.mainPane->show(); fixture.detailPane->show(); }
    }
    settle();
    const QString final = fixture.snapshot();
    check(observer.paints > 0, "no natural Paint observed");
    check(fixture.host && fixture.host->isBound(), "host did not bind complete panels");
    check(observer.first == final, "layout changed after the first natural Paint");
    check(fixture.host->effectiveScheme() == scheme, "requested layout scheme was not applied");
    check(scheme == DetailDisplayScheme::Right ? !fixture.detailPane->isHidden() : fixture.detailPane->isHidden(),
        "detail panel visibility disagrees with its requested scheme");
    if (keepHidden) check(fixture.splitter->isHidden(), "explicitly hidden splitter was forced visible");
    if (observer.first != final)
        std::fprintf(stderr, "FIRST [%s] %s\nFINAL [%s] %s\n", qPrintable(caseName), qPrintable(observer.first), qPrintable(caseName), qPrintable(final));
    qApp->removeEventFilter(&observer);
}
void reentrantBoundary(bool deleteHost, bool compatibilityWrapper = false)
{
    caseName = deleteHost ? QStringLiteral("host-deleted-during-scheme-hide")
                          : QStringLiteral("view-rebound-during-scheme-hide");
    if (compatibilityWrapper) caseName += QStringLiteral("-compat-wrapper-show");
    std::fprintf(stderr, "REENTRANT_BOUNDARY=%s\n", qPrintable(caseName));
    Fixture fixture;
    fixture.panels(!compatibilityWrapper, true);
    fixture.createHost(!compatibilityWrapper);
    auto* replacement = new QTableWidget(2, 1, fixture.mainPane);
    fixture.mainPane->layout()->addWidget(replacement);
    const auto scheme = compatibilityWrapper ? DetailDisplayScheme::Right : DetailDisplayScheme::Embedded;
    fixture.host->applyScheme(scheme);
    BoundaryAction boundary;
    if (compatibilityWrapper) {
        boundary.trigger = QEvent::Show;
        boundary.ready = [&fixture] { return fixture.host && fixture.host->isBound(); };
    }
    boundary.action = [&fixture, replacement, deleteHost] {
        if (deleteHost) delete fixture.host.data();
        else fixture.host->setTableView(replacement);
    };
    QWidget* watched = compatibilityWrapper ? fixture.mainPane.data() : fixture.detailPane.data();
    watched->installEventFilter(&boundary);
    fixture.owner.show();
    settle();
    check(boundary.called, "scheme did not exercise the synchronous visibility callback");
    if (deleteHost) {
        check(fixture.host.isNull(), "host deletion was lost across the layout callback");
        check(fixture.owner.showsToParent == 1, "surviving owner's original ShowToParent event was swallowed");
    }
    else check(fixture.host && fixture.host->isBound()
               && fixture.host->effectiveScheme() == scheme
               && fixture.detailPane->isHidden() == !compatibilityWrapper,
               "reentrant view binding did not settle in its requested scheme");
    watched->removeEventFilter(&boundary);
}
}
int main(int argc, char** argv)
{
    QApplication app(argc, argv);
    for (bool embeddedOwner : {false, true}) {
        for (bool explicitBinding : {false, true})
            for (bool existingSplitter : {false, true}) {
                if (explicitBinding && !existingSplitter) continue;
                for (bool visibleOwner : {false, true})
                    for (bool late : {false, true})
                        for (int backlog : {0, 200})
                            for (auto scheme : {DetailDisplayScheme::BottomCollapsed, DetailDisplayScheme::Embedded, DetailDisplayScheme::Right, DetailDisplayScheme::Floating})
                                exercise(explicitBinding, existingSplitter, visibleOwner, late, backlog, scheme, false, embeddedOwner);
            }
        for (bool explicitBinding : {false, true})
            for (bool visibleOwner : {false, true})
                exercise(explicitBinding, true, visibleOwner, false, 200, DetailDisplayScheme::Right, true, embeddedOwner);
    }
    reentrantBoundary(false);
    reentrantBoundary(true);
    reentrantBoundary(false, true);
    reentrantBoundary(true, true);
    for (auto scheme : {DetailDisplayScheme::BottomCollapsed, DetailDisplayScheme::Embedded, DetailDisplayScheme::Right, DetailDisplayScheme::Floating}) {
        caseName = QStringLiteral("visibility gate %1").arg(int(scheme));
        Fixture fixture; fixture.panels(true, true); fixture.createHost(true);
        fixture.host->setDetailsEnabled(false); fixture.host->applyScheme(scheme); fixture.showOwner(); settle();
        check(fixture.host->isBound() && fixture.detailPane->isHidden(), "disabled detail remains hidden at first show");
        fixture.host->setDetailsEnabled(true); settle();
        check(fixture.host->effectiveScheme() == scheme, "enabling keeps requested scheme");
        check(fixture.detailPane->isHidden() == (scheme != DetailDisplayScheme::Right), "enabling applies scheme visibility");
        fixture.host->setDetailsEnabled(false); settle();
        check(fixture.detailPane->isHidden(), "disabling hides detail again");
    }
    std::printf("DETAIL_FIRST_FRAME_CASES=%d CHECKS=%d FAILURES=%d NATURAL_PAINT=1 MAIN_GUI=0 CORE_METHODS_UNMODIFIED=1\n", cases, checks, failures);
    return failures ? 1 : 0;
}
