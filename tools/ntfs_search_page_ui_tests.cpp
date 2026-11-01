#include "ntfs_qt_umbrella.h"
#include <atomic>
#include <iostream>
#include <memory>
#include <QFontDatabase>
#include <QFontMetrics>
#include <QKeyEvent>
#include <stdexcept>

#define private public
#include "FileDock/NtfsSearchPage.h"
#include "FileDock/NtfsSpaceMapWidget.h"
#undef private
#include "ntfs_search_page_source.inc"
#include "ntfs_path_source.inc"
#include "UI/MainSurfaceStyle.h"
#include "UI/PageTabMotion.h"
#include "UI/TableInteractionSupport.h"
#include "UI/TableSearchSupport.h"

namespace {
std::atomic<int> backendMode{0}, entered{0};
std::atomic_bool releaseBackend{false};
int checks = 0;
class FirstPaint final : public QObject
{
public:
    std::function<QVector<QRect>()> geometry;
    QVector<QRect> first;
    bool observed = false;
    bool eventFilter(QObject* object, QEvent* event) override
    {
        if (event->type() == QEvent::Paint && !observed) {
            observed = true; first = geometry();
        }
        return QObject::eventFilter(object, event);
    }
};
void check(bool condition, const char* message)
{
    ++checks;
    if (!condition) throw std::runtime_error(message);
}
void prepareTestFont(QApplication& app)
{
#ifdef Q_OS_WIN
    // The Windows offscreen plugin does not reliably discover system CJK
    // families. Register only these known files so layout uses real glyphs.
    const QString fonts = qEnvironmentVariable("WINDIR", QStringLiteral("C:/Windows")) + QStringLiteral("/Fonts/");
    QStringList families;
    for (const auto* name : {"msyh.ttc", "msyhbd.ttc"}) {
        const int id = QFontDatabase::addApplicationFont(fonts + QString::fromLatin1(name));
        if (id >= 0) families = QFontDatabase::applicationFontFamilies(id);
        if (!families.isEmpty()) break;
    }
    check(!families.isEmpty(), "known Windows YaHei font must load for Chinese UI geometry");
    QFont font = app.font();
    const QString preferred = QStringLiteral("Microsoft YaHei UI");
    font.setFamily(families.contains(preferred) ? preferred : families.front());
    app.setFont(font);
    const QFontMetrics metrics(app.font());
    for (const QChar character : QStringLiteral("扫描搜索磁盘文件"))
        check(metrics.inFont(character), "test font must contain the Chinese workflow glyphs");
    std::cout << "NTFS_UI_FONT=PASS family=" << app.font().family().toStdString() << " CHINESE=1\n";
#else
    Q_UNUSED(app);
#endif
}
template<class Predicate> void until(Predicate done, const char* message)
{
    QElapsedTimer elapsed; elapsed.start();
    while (!done() && elapsed.elapsed() < 5000) {
        QCoreApplication::processEvents(QEventLoop::AllEvents, 5);
        QThread::msleep(1);
    }
    check(done(), message);
}
void drain()
{
    for (int i = 0; i < 20; ++i) {
        QCoreApplication::processEvents(QEventLoop::AllEvents, 5);
        QThread::msleep(1);
    }
}
void pressEnter(QLineEdit* field)
{
    field->setFocus();
    QKeyEvent pressed(QEvent::KeyPress, Qt::Key_Return, Qt::NoModifier);
    QKeyEvent released(QEvent::KeyRelease, Qt::Key_Return, Qt::NoModifier);
    QCoreApplication::sendEvent(field, &pressed);
    QCoreApplication::sendEvent(field, &released);
}
QString visibleLabels(QWidget* page)
{
    QStringList labels;
    for (auto* label : page->findChildren<QLabel*>())
        if (label->isVisibleTo(page)) labels.push_back(label->text());
    return labels.join(QLatin1Char('\n'));
}
ks::files::NtfsFastIndex::Snapshot fakeSnapshot(const QString& root,
    const ks::files::NtfsFastIndex::Cancel& cancel)
{
    ++entered;
    const int mode = backendMode.load();
    while (mode == 2 && !releaseBackend.load() && !(cancel && cancel->load())) QThread::msleep(1);
    if (mode == 3) throw std::runtime_error("controlled backend exception");
    if (mode == 4) return {};
    auto value = std::make_shared<ks::files::NtfsIndexSnapshot>();
    value->volumeRoot = root; value->rootReference = 5;
    if (cancel && cancel->load()) { value->cancelled = true; return value; }
    if (mode == 0 || mode == 5) {
        value->error = QStringLiteral("Controlled Win32 error 5"); value->rebuildRequired = mode == 5; return value;
    }
    value->complete = true; value->journalAvailable = true;
    ks::files::NtfsIndexEntry rootEntry;
    rootEntry.fileReference = 5; rootEntry.parentReference = 5; rootEntry.name = root; rootEntry.attributes = 0x10;
    value->entries.insert(5, rootEntry);
    auto directory = rootEntry;
    directory.fileReference = 7; directory.parentReference = 5; directory.name = QStringLiteral("folder");
    value->entries.insert(7, directory);
    ks::files::NtfsIndexEntry file;
    file.fileReference = 9; file.parentReference = 7; file.name = QStringLiteral("sample.txt");
    file.sizeKnown = true; file.logicalBytes = 100; file.allocatedBytes = 4096;
    value->entries.insert(9, file);
    return value;
}
}

namespace ks::files {
NtfsFastIndex::Snapshot NtfsFastIndex::build(const QString& root, const Cancel& cancel, const Progress& progress)
{
    if (progress) progress(0, 0);
    return fakeSnapshot(root, cancel);
}
NtfsFastIndex::Snapshot NtfsFastIndex::refresh(const Snapshot& previous, const Cancel& cancel, const Progress& progress)
{
    return build(previous->volumeRoot, cancel, progress);
}
}

// The actual page/widgets/themes/async/result commit coordinator are linked.
// These absent product integrations retain only the declared boundary:
// translation pack loading, tab motion/glyph files, unrelated editor types and table actions.
namespace ks::i18n {
struct LanguageManager::State {};
LanguageManager::LanguageManager() = default;
LanguageManager::~LanguageManager() = default;
bool LanguageManager::eventFilter(QObject* object, QEvent* event) { return QObject::eventFilter(object, event); }
LanguageManager& LanguageManager::instance() { static LanguageManager value; return value; }
QString LanguageManager::sourceText(const QString& value) const { return value; }
QString LanguageManager::displayText(const QString& value) const { return value; }
void LanguageManager::bindText(QObject* object, const QString&, const QString& value)
{
    if (auto* group = qobject_cast<QGroupBox*>(object)) group->setTitle(value);
    else object->setProperty("text", value);
}
void LanguageManager::bindToolTip(QWidget* object, const QString&, const QString& value) { object->setToolTip(value); }
void LanguageManager::bindPlaceholder(QLineEdit* object, const QString&, const QString& value) { object->setPlaceholderText(value); }
void LanguageManager::bindComboBoxItem(QComboBox* object, int item, const QString&, const QString& value) { object->setItemText(item, value); }
void LanguageManager::bindTab(QTabWidget* object, QWidget* page, const QString&, const QString& value) { object->setTabText(object->indexOf(page), value); }
bool LanguageManager::moveTextBinding(QObject*, QObject*, bool) { return false; }
}
namespace ks::ui {
QString ThemedControlGlyphPath(const QString&, const QColor&, const QString&) { return {}; }
void InstallPageTabMotion(QTabBar*, std::function<PageTabMotionColors()>) {}
void InstallParentTabTransition(QTabWidget*) {}
void InstallChildTabTransition(QTabWidget*) {}
void ConfigureResultTableInteractions(QTableView* table, const ResultTableCapabilities& capabilities)
{
    if (capabilities.actionBar) table->setProperty(TableActionBarModeProperty, int(*capabilities.actionBar));
}
void PrepareTableSearchModelChange(QTableView*) {}
void RefreshTableSearchModelBinding(QTableView*) {}
}

namespace {
void prepareVolume(NtfsSearchPage& page)
{
    auto& s = *page.m_state;
    s.volumeOperation->cancel(); s.discovering = false;
    s.volume->clear(); s.volume->addItem(QStringLiteral("Controlled NTFS"), QStringLiteral("T:\\"));
    s.indexText.set(s.indexStatus, "选择磁盘，输入文件名或关键词，然后点击“扫描并搜索”。");
    page.updateButtons();
}
QColor sample(QWidget* widget, QPoint point)
{
    return widget->grab().toImage().pixelColor(point);
}
void runPage(bool dark)
{
    KswordTheme::SetDarkModeEnabled(dark);
    QPalette palette;
    palette.setColor(QPalette::Window, KswordTheme::WindowColor());
    palette.setColor(QPalette::WindowText, KswordTheme::TextPrimaryColor());
    palette.setColor(QPalette::Base, KswordTheme::SurfaceColor());
    palette.setColor(QPalette::Text, KswordTheme::TextPrimaryColor());
    qApp->setPalette(palette);
    QWidget root;
    root.setProperty("ksword_main_surface_hierarchy", true);
    root.setStyleSheet(ks::ui::BuildMainSurfaceStyle(false));
    auto* layout = new QVBoxLayout(&root);
    auto* page = new NtfsSearchPage(&root); layout->addWidget(page);
    prepareVolume(*page);
    FirstPaint first;
    first.geometry = [&] {
        const auto& state = *page->m_state;
        return QVector<QRect>{state.tabs->geometry(), state.results->geometry(),
            state.results->viewport()->geometry(), state.results->horizontalHeader()->geometry(),
            state.indexStatus->parentWidget()->geometry(), state.searchStatus->parentWidget()->geometry()};
    };
    root.installEventFilter(&first);
    root.resize(1280, 800); root.show();
    until([&] { return !page->m_state->volumeOperation->isInFlight(); }, "volume discovery settles");
    drain();
    auto& s = *page->m_state;
    check(first.observed && first.first == first.geometry(), "real MFT first paint has settled result/header/viewport geometry");
    const QString artifactDirectory = qEnvironmentVariable("KSWORD_NTFS_UI_ARTIFACT_DIR");
    if (!artifactDirectory.isEmpty()) {
        QDir().mkpath(artifactDirectory);
        root.grab().save(artifactDirectory + (dark ? QStringLiteral("/dark-initial.png") : QStringLiteral("/light-initial.png")));
    }
    QWidget* header = s.indexStatus->parentWidget();
    QWidget* toolbar = s.searchStatus->parentWidget();
    const QColor expected = ks::ui::MainWindowSurfaceColors().toolbar;
    check(sample(toolbar, QPoint(toolbar->width() / 2, 1)) == expected, "search toolbar paints shared surface without black strip");
    check(s.tabs->property("ksword_joined_result_tabs").toBool(), "MFT result tabs use shared joined relationship");
    check(s.tabs->property("ksword_page_tabs_content_inset").toInt() == 0, "MFT result pages have no repeated side inset");
    check(header->property("ksword_primary_toolbar").toBool(), "shared index state owns joined header surface");
    check(toolbar->property("ksword_primary_toolbar").toBool(), "search state/actions own shared toolbar surface");
    check(dynamic_cast<ks::ui::TableActionTableView*>(s.results), "search results use shared table chrome reservation");
    check(dynamic_cast<ks::ui::TableActionTableView*>(s.extensions), "extension results use shared table chrome reservation");
    check(ks::ui::ResultTableHost::ensure(s.results)->capabilities().actionBar == ks::ui::TableActionBarMode::Compact,
        "search result keeps compact shared action mode");
    check(sample(header, QPoint(header->width() / 2, 1)) == expected, "joined result header paints shared surface");
    check(sample(s.tabs, QPoint(s.tabs->width() - 12, s.tabs->tabBar()->height() / 2)) == expected,
        "full tab rail joins the shared toolbar surface");
    check(sample(s.results->horizontalHeader(), QPoint(12, 1)) == ks::ui::MainWindowSurfaceColors().header,
        "result table header keeps shared header surface");
    check(s.query->isEnabled() && s.search->isEnabled() && !s.up->isEnabled() && !s.locate->isEnabled(),
        "first-time search is available while result-dependent actions remain unavailable");
    check(s.search->text() == QStringLiteral("扫描并搜索"), "first-time primary action explains the complete scan-and-search workflow");
    check(s.search->parentWidget() == s.cancel->parentWidget() && s.search->isVisibleTo(page),
        "primary search and stop remain together in the fixed execution area");
    check(s.progress->parentWidget() == s.indexStatus->parentWidget(),
        "preparation progress stays with its visible common status");
    check(s.searchType->currentIndex() == 0 && !s.fullPath->isChecked() && !s.wildcard->isChecked(),
        "novice search defaults are name fragments across files and directories");
    check(visibleLabels(page).contains(QStringLiteral("首次搜索")), "visible guidance explains automatic first-time file-list preparation");

    s.query->setText(QStringLiteral("sample"));
    backendMode = 0; s.search->click();
    check(s.indexing && s.cancel->isEnabled() && !s.build->isEnabled(), "primary search immediately enters cancellable file-list preparation");
    check(s.build->text().contains(QStringLiteral("正在")), "build busy text responds immediately");
    check(s.searchStatus->text().contains(QStringLiteral("正在准备")), "search area explains initial file-list preparation");
    until([&] { return !s.indexOperation->isBusy(); }, "controlled build failure returns");
    check(!s.projection && s.search->isEnabled(), "failed first-time scan restores primary retry without inventing a usable index");
    check(s.indexStatus->text().contains(QStringLiteral("Controlled Win32 error 5")), "real backend error is visible in common result header");
    check(s.searchStatus->text().contains(QStringLiteral("未能加载")) && s.spaceStatus->text().contains(QStringLiteral("未能加载")),
        "both result tabs explain index failure");
    check(s.build->isEnabled() && s.search->text() == QStringLiteral("扫描并搜索"), "failure leaves an explicit enabled scan-and-search retry");
    check(!s.cancel->isEnabled() && s.progress->isHidden(), "failure settles cancel and progress state");
    backendMode = 3; s.build->click();
    until([&] { return !s.indexOperation->isBusy(); }, "backend exception settles");
    check(!s.projection && s.build->isEnabled() && !s.cancel->isEnabled() && s.progress->isHidden(),
        "backend exception restores retry controls without claiming a usable index");
    backendMode = 4; s.build->click();
    until([&] { return !s.indexOperation->isBusy(); }, "missing backend result settles");
    check(!s.projection && s.indexStatus->text().contains(QStringLiteral("未能加载")),
        "missing backend result is a failure rather than a fake user cancellation");
    s.tabs->setCurrentIndex(1); drain();
    check(s.spaceStatus->parentWidget()->property("ksword_primary_toolbar").toBool(), "space state/actions share toolbar surface");
    check(sample(s.spaceStatus->parentWidget(), QPoint(s.spaceStatus->parentWidget()->width() / 2, 1)) == expected,
        "space toolbar paints shared surface without black strip");

    backendMode = 2; releaseBackend = false; s.build->click();
    until([&] { return s.indexOperation->isInFlight(); }, "cancellable backend starts");
    s.cancel->click();
    check(s.cancelToken->load() && !s.cancel->isEnabled(), "cancel click immediately signals index token and prevents duplicate cancel");
    until([&] { return !s.indexOperation->isBusy(); }, "cancelled build settles");
    check(!s.indexing && s.build->isEnabled() && s.progress->isHidden(), "cancel restores actionable idle state");
    check(s.searchStatus->text().contains(QStringLiteral("已停止")), "cancelled initial index remains clearly unavailable");

    backendMode = 1; s.query->clear();
    const int beforeEnter = entered.load();
    pressEnter(s.query);
    until([&] { return !s.indexOperation->isBusy() && !s.searchOperation->isBusy() && !s.spaceOperation->isBusy(); }, "successful fixture index/search/space settle");
    check(entered.load() > beforeEnter, "Enter before an index exists starts automatic preparation");
    check(s.projection && s.search->isEnabled() && s.refresh->isEnabled(), "usable index enables search and USN refresh");
    check(s.search->text() == QStringLiteral("搜索") && visibleLabels(page).contains(QStringLiteral("T:\\")),
        "ready workflow names the indexed volume and exposes direct search");
    check(s.searchModel->rowCount() == 3 && s.extensionModel->rowCount() == 1, "automatic search and extension projections populate real models");
    check(s.map->m_data->items.size() == 1, "space map receives prepared direct-directory data");
    const auto rootMap = s.map->m_data;
    auto* commits = ks::ui::UiCommitCoordinator::forApplication();
    commits->beginContextMenu(s.extensions);
    page->showDirectory(7);
    until([&] { return commits->pendingCount() > 0; }, "space navigation reaches real deferred table commit barrier");
    check(s.currentDirectory == 7 && s.map->m_data == rootMap, "in-progress space navigation keeps last committed map");
    s.cancel->click();
    check(s.currentDirectory == 5 && s.mapPath->text() == QStringLiteral("T:\\") && s.map->m_data == rootMap,
        "space cancellation restores matching committed directory identity/path/map");
    commits->endContextMenu(s.extensions);
    until([&] { return commits->pendingCount() == 0; }, "cancelled deferred space commit drains");
    check(s.currentDirectory == 5 && s.map->m_data == rootMap && !s.up->isEnabled(),
        "cancelled deferred action cannot replace restored result or parent navigation");
    page->showDirectory(7);
    until([&] { return !s.spaceOperation->isBusy(); }, "directory navigation retry settles");
    check(s.currentDirectory == 7 && s.up->isEnabled() && s.mapPath->text() == QStringLiteral("T:\\folder"),
        "directory navigation retry commits correct identity and parent action");
    s.up->click();
    until([&] { return !s.spaceOperation->isBusy(); }, "parent navigation button settles");
    check(s.currentDirectory == 5 && !s.up->isEnabled(), "parent navigation returns to indexed volume root");
    s.mapMetric->setCurrentIndex(1);
    until([&] { return !s.spaceOperation->isBusy(); }, "logical-size mode settles");
    check(s.map->m_data->items.size() == 1 && s.map->m_data->items.front().bytes == 100,
        "space metric preserves actual logical/allocated size semantics");
    s.tabs->setCurrentIndex(0); s.query->setText(QStringLiteral("folder")); s.search->click();
    s.cancel->click();
    check(s.searchStatus->text().contains(QStringLiteral("已停止")) && s.search->isEnabled() && s.searchModel->rowCount() == 3,
        "search cancellation keeps committed result and restores enabled search");
    until([&] { return !s.searchOperation->isInFlight(); }, "cancelled search worker returns through async gate");
    check(s.searchModel->rowCount() == 3, "cancelled search cannot later overwrite retained model");
    s.tabs->setCurrentIndex(0); s.query->setText(QStringLiteral("sample")); s.search->click();
    check(s.searchOperation->isBusy() && !s.search->isEnabled() && s.cancel->isEnabled(), "search click has cancellable busy feedback");
    until([&] { return !s.searchOperation->isBusy(); }, "search query settles");
    check(s.searchModel->rowCount() == 1, "search preserves query semantics");
    s.query->setText(QStringLiteral("FOLDER\\SAMPLE"));
    pressEnter(s.query);
    until([&] { return !s.searchOperation->isBusy(); }, "name-only Enter search settles");
    check(s.searchModel->rowCount() == 0, "default name search does not silently match full directory paths");
    s.fullPath->setChecked(true); pressEnter(s.query);
    until([&] { return !s.searchOperation->isBusy(); }, "full-path Enter search settles");
    check(s.searchModel->rowCount() == 1, "explicit full-path matching preserves case-insensitive query semantics");
    s.fullPath->setChecked(false); s.wildcard->setChecked(true); s.query->setText(QStringLiteral("*.TXT"));
    pressEnter(s.query);
    until([&] { return !s.searchOperation->isBusy(); }, "wildcard search settles");
    check(s.searchModel->rowCount() == 1, "explicit wildcard option matches file extensions");
    s.wildcard->setChecked(false); s.query->clear(); s.searchType->setCurrentIndex(1); pressEnter(s.query);
    until([&] { return !s.searchOperation->isBusy(); }, "files-only search settles");
    check(s.searchModel->rowCount() == 1, "files-only filter excludes root and child directories");
    s.searchType->setCurrentIndex(2); pressEnter(s.query);
    until([&] { return !s.searchOperation->isBusy(); }, "directories-only search settles");
    check(s.searchModel->rowCount() == 2, "directories-only filter excludes files");
    s.searchType->setCurrentIndex(0); s.query->setText(QStringLiteral("sample")); pressEnter(s.query);
    until([&] { return !s.searchOperation->isBusy(); }, "ordinary Enter search restores selected-file results");
    s.results->setCurrentIndex(s.searchModel->index(0, 0));
    check(s.locate->isEnabled(), "valid selected path enables locate");
    QString located;
    QObject::connect(page, &NtfsSearchPage::locatePathRequested, page, [&](const QString& path) { located = path; });
    s.locate->click();
    check(located == QStringLiteral("T:\\folder\\sample.txt"), "locate emits the real projected selected path");
    const auto old = s.projection;
    backendMode = 0; s.refresh->click();
    until([&] { return !s.indexOperation->isBusy(); }, "failed refresh settles");
    check(s.projection == old && s.searchModel->rowCount() == 1, "failed refresh preserves usable snapshot and search results");
    check(s.search->isEnabled() && s.indexStatus->text().contains(QStringLiteral("保留")), "failed refresh explains retained usable index");
    backendMode = 5; s.refresh->click();
    until([&] { return !s.indexOperation->isBusy(); }, "invalid journal refresh settles");
    check(s.projection == old && !s.refresh->isEnabled() && s.build->isEnabled(),
        "invalid journal retains usable snapshot and requires full rebuild");
    backendMode = 1; s.build->click();
    until([&] { return !s.indexOperation->isBusy() && !s.searchOperation->isBusy() && !s.spaceOperation->isBusy(); }, "full rebuild after invalid journal settles");
    check(s.refresh->isEnabled(), "successful full rebuild restores incremental refresh availability");
    s.discovering = true; page->updateButtons();
    const int beforeDiscovery = entered.load();
    check(!s.refresh->isEnabled(), "volume discovery disables USN refresh alongside build");
    page->startIndex(true);
    check(!s.indexing && entered.load() == beforeDiscovery, "index entry rejects overlapping volume discovery");
    s.discovering = false; page->updateButtons();
    const auto previousVolume = s.projection;
    const int retainedRows = s.searchModel->rowCount();
    commits->beginContextMenu(s.results);
    s.query->setText(QStringLiteral("folder")); page->startSearch();
    until([&] { return commits->pendingCount() > 0; }, "old-volume search reaches a deferred result commit");
    s.volume->addItem(QStringLiteral("Another controlled NTFS"), QStringLiteral("U:\\"));
    s.volume->setCurrentIndex(1);
    commits->endContextMenu(s.results);
    until([&] { return commits->pendingCount() == 0 && !s.searchOperation->isBusy(); },
        "target-volume change retires the old deferred search");
    check(s.searchModel->rowCount() == retainedRows,
        "an old-volume deferred search cannot overwrite retained results after target selection changes");
    check(s.search->isEnabled() && !s.refresh->isEnabled() && !s.mapMetric->isEnabled()
        && !s.directories->isEnabled() && !s.map->isEnabled() && !s.locate->isEnabled() && !s.up->isEnabled(),
        "switching target volume leaves search available and disables actions on the retained old-volume snapshot");
    check(visibleLabels(page).contains(QStringLiteral("T:\\")) && visibleLabels(page).contains(QStringLiteral("U:\\")),
        "volume mismatch visibly distinguishes retained result volume from the selected target");
    located.clear(); page->locateSelected();
    check(located.isEmpty(), "direct locate cannot act on a retained snapshot from a different selected volume");
    const auto previousDirectory = s.currentDirectory;
    page->showDirectory(7);
    check(s.currentDirectory == previousDirectory && !s.spaceOperation->isBusy(),
        "direct space navigation cannot run against a retained mismatching volume");
    backendMode = 0; s.search->click();
    until([&] { return !s.indexOperation->isBusy(); }, "selected-volume scan failure settles");
    check(s.projection == previousVolume && s.searchModel->rowCount() == retainedRows && s.search->isEnabled(),
        "failed selected-volume preparation preserves old results for retry without searching the old snapshot");
    check(!s.map->isEnabled() && !s.locate->isEnabled(), "failed preparation keeps old-volume navigation unavailable");
    backendMode = 1; s.query->setText(QStringLiteral("sample")); pressEnter(s.query);
    until([&] { return !s.indexOperation->isBusy() && !s.searchOperation->isBusy() && !s.spaceOperation->isBusy(); },
        "Enter prepares and searches the selected replacement volume");
    check(s.projection != previousVolume && s.projection->snapshot->volumeRoot == QStringLiteral("U:\\")
        && s.searchModel->rowCount() == 1 && s.searchModel->row(0)->path == QStringLiteral("U:\\folder\\sample.txt"),
        "a selected-volume search builds the selected volume instead of querying retained old results");
    check(previousVolume->snapshot->volumeRoot == QStringLiteral("T:\\") && s.map->isEnabled(),
        "new-volume commit preserves immutable old identity and re-enables matching space actions");
    root.resize(680, 650); drain();
    check(s.tabs->width() > 200 && s.results->width() == toolbar->width(), "narrow workspace keeps result toolbar and table aligned");
    root.close();
}
void closeDuringIndex()
{
    auto* page = new NtfsSearchPage;
    until([&] { return !page->m_state->volumeOperation->isInFlight(); }, "closing fixture volume probe settles");
    prepareVolume(*page);
    backendMode = 2; releaseBackend = false;
    const int previous = entered.load();
    page->m_state->build->click();
    until([&] { return entered.load() > previous; }, "closing fixture raw worker is active");
    const auto token = page->m_state->cancelToken;
    QPointer<NtfsSearchPage> guard(page);
    delete page;
    check(guard.isNull() && token->load(), "page close immediately cancels raw operation and destroys owner");
    check(QThreadPool::globalInstance()->waitForDone(5000), "closed page worker retires without UI ownership");
    drain();
}
}

int main(int argc, char** argv)
{
    QApplication app(argc, argv);
    auto* commits = new ks::ui::UiCommitCoordinator(&app, {[] { return false; }, [] { return false; }});
    commits->setObjectName(QStringLiteral("ksword_ui_commit_coordinator"));
    try {
        prepareTestFont(app);
        runPage(false); runPage(true); closeDuringIndex();
        QThreadPool::globalInstance()->waitForDone();
        std::cout << "NTFS_SEARCH_PAGE_UI_PASS checks=" << checks << '\n';
        return 0;
    } catch (const std::exception& error) {
        releaseBackend = true;
        std::cerr << "NTFS_SEARCH_PAGE_UI_FAIL: " << error.what() << '\n';
        return 1;
    }
}
