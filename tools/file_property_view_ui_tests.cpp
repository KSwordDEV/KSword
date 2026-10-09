// Exercises the production native property view, without accessing a target
// file, a driver or the system clipboard. Payload snapshots are pure strings.
#include "../Ksword5.1/Ksword5.1/FileDock/FilePropertyView.h"
#include "../Ksword5.1/Ksword5.1/Internationalization/LanguageManager.h"

#include <QApplication>
#include <QDir>
#include <QEvent>
#include <QFontDatabase>
#include <QLineEdit>
#include <QMenu>
#include <QPlainTextEdit>
#include <QScrollBar>
#include <QShortcut>
#include <QTest>
#include <QTextEdit>
#include <QTreeWidget>
#include <cstdlib>
#include <iostream>

using namespace file_dock_detail;

namespace
{
    unsigned checks = 0;
    void require(const bool condition, const char* explanation)
    {
        ++checks;
        if (!condition) { std::cerr << "FAIL [" << checks << "]: " << explanation << '\n'; std::exit(1); }
    }
    void flush()
    {
        QCoreApplication::processEvents();
        QTest::qWait(10);
        QCoreApplication::processEvents();
    }
    PropertyDocument fixture()
    {
        PropertyDocument document;
        document.title = QStringLiteral("文件属性");
        document.field(QStringLiteral("文件名"), QStringLiteral("KSword.exe"));
        document.section(QStringLiteral("常规"))
            .field(QStringLiteral("完整路径"), QStringLiteral("C:\\Tools\\<b>KSword</b>\\KSword.exe"))
            .field(QStringLiteral("文件属性"), QStringLiteral("正常"), true)
            .field(QStringLiteral("Long value"), QString(420, QLatin1Char('X')))
            .note(QStringLiteral("<a href=\"file:///untrusted\">plain note</a>\nsecond line"));
        PropertyNode parent;
        parent.name = QStringLiteral("Nested parent");
        parent.value = QStringLiteral("root value");
        PropertyNode child;
        child.name = QStringLiteral("Hidden child");
        child.value = QStringLiteral("needle in nested value");
        parent.children.append(child);
        document.nodes.last().children.append(parent);
        document.section(QStringLiteral("Other section"))
            .field(QStringLiteral("Duplicate"), QStringLiteral("first"))
            .field(QStringLiteral("Duplicate"), QStringLiteral("second"));
        return document;
    }

    void setTheme(const bool dark)
    {
        QPalette palette;
        for (const auto group : {QPalette::Active, QPalette::Inactive, QPalette::Disabled})
        {
            const QColor background = dark ? QColor(34, 37, 42) : QColor(250, 251, 253);
            const QColor alternate = dark ? QColor(44, 48, 54) : QColor(235, 239, 245);
            const QColor text = dark ? QColor(239, 242, 246) : QColor(27, 32, 40);
            palette.setColor(group, QPalette::Window, background);
            palette.setColor(group, QPalette::Base, background);
            palette.setColor(group, QPalette::AlternateBase, alternate);
            palette.setColor(group, QPalette::Button, alternate);
            palette.setColor(group, QPalette::Text, text);
            palette.setColor(group, QPalette::WindowText, text);
            palette.setColor(group, QPalette::ButtonText, text);
            palette.setColor(group, QPalette::PlaceholderText, dark ? QColor(160, 165, 174) : QColor(90, 99, 111));
            palette.setColor(group, QPalette::Highlight, QColor(0, 111, 221));
            palette.setColor(group, QPalette::HighlightedText, Qt::white);
            palette.setColor(group, QPalette::Mid, dark ? QColor(71, 77, 87) : QColor(199, 207, 219));
        }
        qApp->setPalette(palette);
        flush();
    }
}

int main(int argc, char** argv)
{
    QApplication application(argc, argv);
    const auto families = QFontDatabase::families();
    for (const auto& family : {QStringLiteral("Microsoft YaHei UI"), QStringLiteral("Microsoft YaHei")})
        if (families.contains(family)) { application.setFont(QFont(family, 10)); break; }
    QString languageError;
    require(ks::i18n::LanguageManager::instance().initialize(QStringLiteral("zh-CN"), &languageError),
        "actual language packs initialize");
    const QString shots = argc > 1 ? QString::fromLocal8Bit(argv[1]) : QString();
    if (!shots.isEmpty()) require(QDir().mkpath(shots), "create owned fixture preview directory");

    auto document = fixture();
    require(document.nodes.size() == 3, "document owns explicit ungrouped field and two sections");
    require(document.nodes[1].children.size() == 5, "section owns values and explicit note nodes");
    require(document.toPlainText().contains(QStringLiteral("<b>KSword</b>")), "export preserves HTML-like raw value");
    require(document.toPlainText().contains(QStringLiteral("Hidden child: needle")), "export includes nested typed child");
    FilePropertyView view;
    view.resize(760, 330);
    view.setDocument(document);
    view.show();
    flush();
    auto* tree = view.tree();
    require(view.presentation() == FilePropertyView::Presentation::Sections, "default partition presentation");
    require(tree->columnCount() == 2 && !tree->rootIsDecorated(), "native partition fields with two columns");
    require(view.findChildren<QTextEdit*>().isEmpty() && view.findChildren<QPlainTextEdit*>().isEmpty(),
        "no text editor or report text substrate exists");
    require(tree->font().pointSizeF() == application.font().pointSizeF(), "normal application font without 1.6x scaling");
    require(tree->topLevelItemCount() == 3 && tree->topLevelItem(1)->childCount() == 5,
        "native items preserve every typed node");
    auto* general = tree->topLevelItem(1);
    auto* nested = general->child(4);
    require(nested->isExpanded(), "nested property initially exposes its children");
    require(general->child(0)->text(1).contains(QStringLiteral("<b>KSword</b>")), "native value is literal HTML-like text");
    require(general->child(3)->isFirstColumnSpanned(), "notes span both columns");
    const auto baselineText = view.plainText();
    const auto shortHeight = tree->visualItemRect(general->child(0)).height();
    const auto longHeight = tree->visualItemRect(general->child(2)).height();
    require(longHeight > shortHeight && longHeight > 2 * QFontMetrics(tree->font()).height() + 14,
        "long unbroken values wrap to more than two native visual lines");
    require(tree->verticalScrollBar()->maximum() > 0, "native scrolling reaches long content");

    general->setExpanded(false);
    nested->setExpanded(false);
    view.setSearchText(QStringLiteral("NEEDLE"));
    flush();
    require(!general->isHidden() && general->isExpanded(), "descendant match reveals and expands its group");
    require(!nested->isHidden() && nested->isExpanded() && !nested->child(0)->isHidden(),
        "case insensitive search reveals collapsed nested child");
    require(general->child(0)->isHidden() && tree->topLevelItem(2)->isHidden(), "unmatched sibling data filtered");
    require(view.plainText() == baselineText, "filter does not truncate all-information export");
    view.setSearchText(QString());
    require(!general->isExpanded() && !nested->isExpanded(), "clear search restores both prior expansion states");
    view.setSearchText(QStringLiteral("常规"));
    require(!general->child(0)->isHidden() && !nested->child(0)->isHidden(), "matching section includes all descendants");
    view.setSearchText(QStringLiteral("no-match-xyz"));
    for (int i = 0; i < tree->topLevelItemCount(); ++i)
        require(tree->topLevelItem(i)->isHidden(), "no match hides every root");
    view.setSearchText(QString());
    general->setExpanded(true);
    auto* other = tree->topLevelItem(2);
    tree->setCurrentItem(other->child(1));
    other->child(1)->setSelected(true);
    const auto copied = view.captureCopy(tree->indexFromItem(other->child(1), 0));
    require(copied.hasRow && copied.value == QStringLiteral("second") && copied.row == QStringLiteral("Duplicate: second"),
        "copy snapshot preserves row identity despite duplicate names");
    require(copied.all == baselineText, "copy all snapshot includes complete data");
    require(view.selectedText() == QStringLiteral("Duplicate: second"), "selected rows copy in document order");
    other->setExpanded(false);
    document.nodes[2].children[1].value = QStringLiteral("second refreshed");
    view.setSearchText(QStringLiteral("Duplicate"));
    view.setDocument(document);
    flush();
    require(view.searchText() == QStringLiteral("Duplicate"), "asynchronous refresh retains search text");
    require(tree->currentItem() == tree->topLevelItem(2)->child(1), "refresh preserves duplicate field current identity");
    require(view.selectedText() == QStringLiteral("Duplicate: second refreshed"), "refresh preserves selected source identity");
    require(copied.value == QStringLiteral("second") && copied.all == baselineText, "frozen copy payload survives refresh");
    view.setSearchText(QString());
    require(!tree->topLevelItem(2)->isExpanded(), "refresh while searching retains pre-search expansion");
    view.setPresentation(FilePropertyView::Presentation::Tree);
    require(tree->rootIsDecorated() && view.presentation() == FilePropertyView::Presentation::Tree,
        "tree style shows native branches");
    require(view.selectedText() == QStringLiteral("Duplicate: second refreshed"), "style changes preserve selection");
    FilePropertyView laterView;
    require(laterView.presentation() == FilePropertyView::Presentation::Tree, "new view remembers last style in this session");
    require(view.plainText().contains(QStringLiteral("second refreshed")), "style changes retain values");
    const auto shortcuts = tree->findChildren<QShortcut*>();
    require(shortcuts.size() == 1 && shortcuts.front()->key() == QKeySequence::Copy &&
        shortcuts.front()->context() == Qt::WidgetWithChildrenShortcut, "native Ctrl+C is scoped to this property tree");
    const auto emptySnapshot = view.captureCopy(QModelIndex());
    require(!emptySnapshot.hasRow && !emptySnapshot.all.isEmpty(), "blank context still has copy-all payload");

    tree->topLevelItem(1)->setExpanded(true);
    require(ks::i18n::LanguageManager::instance().setLanguage(QStringLiteral("en-US"), &languageError), "hot English language switch");
    flush();
    require(tree->topLevelItem(1)->text(0) == ks::i18n::sourceText(QStringLiteral("常规")), "source section names retranslate live");
    require(tree->topLevelItem(1)->child(0)->text(0) == ks::i18n::sourceText(QStringLiteral("完整路径")),
        "source field names retranslate live");
    require(tree->topLevelItem(1)->child(0)->text(1).contains(QStringLiteral("<b>KSword</b>")), "hot language does not rewrite raw values");
    require(tree->topLevelItem(1)->child(1)->text(1) == ks::i18n::sourceText(QStringLiteral("正常")),
        "explicit translated value retranslated live");
    require(view.document().nodes[1].name == QStringLiteral("常规"), "stored document retains source names");
    require(ks::i18n::LanguageManager::instance().setLanguage(QStringLiteral("zh-CN"), &languageError), "restore Chinese language");
    flush();
    QFont larger = application.font();
    larger.setPointSize(13);
    application.setFont(larger);
    flush();
    require(tree->font().pointSize() == 13, "hot application font change remains unscaled");
    application.setFont(QFont(larger.family(), 10));
    flush();

    for (const bool dark : {false, true})
    {
        setTheme(dark);
        for (const auto mode : {FilePropertyView::Presentation::Sections, FilePropertyView::Presentation::Tree})
        {
            view.setPresentation(mode);
            tree->topLevelItem(1)->setExpanded(true);
            for (const int width : {760, 320, 200})
            {
                view.resize(width, 330);
                flush();
                require(view.width() == width, "content does not force a wider window");
                require(tree->width() <= width, "tree remains within narrow parent width");
                require(tree->columnWidth(1) >= 48, "narrow viewport retains native value column");
                require(tree->verticalScrollBar()->maximum() > 0, "narrow and themed views keep scrolling");
                require(tree->palette().color(QPalette::Base) == application.palette().color(QPalette::Base),
                    "native palette follows application theme");
                if (!shots.isEmpty() && width != 200)
                {
                    const QString name = QStringLiteral("property-%1-%2-%3.png")
                        .arg(dark ? QStringLiteral("dark") : QStringLiteral("light"))
                        .arg(mode == FilePropertyView::Presentation::Tree ? QStringLiteral("tree") : QStringLiteral("sections"))
                        .arg(width);
                    require(view.grab().save(QDir(shots).filePath(name)), "save actual production view QA preview");
                }
            }
        }
    }
    PropertyDocument large;
    large.section(QStringLiteral("Large result"));
    for (int i = 0; i < 1200; ++i)
        large.field(QStringLiteral("Field %1").arg(i), QString::number(i));
    view.setSearchText(QString());
    view.setDocument(large);
    require(tree->topLevelItem(0)->childCount() == 1200, "large result keeps all typed nodes without per-row widgets");
    require(tree->findChildren<QLineEdit*>().isEmpty(), "fields have no native editor widgets");
    require(tree->findChildren<QTextEdit*>().isEmpty() && tree->findChildren<QPlainTextEdit*>().isEmpty(),
        "large result still has no text document backing");
    view.setSearchText(QStringLiteral("Field 1199"));
    require(!tree->topLevelItem(0)->child(1199)->isHidden(), "search reaches final result beyond screen");
    require(tree->topLevelItem(0)->child(0)->isHidden(), "large search hides unrelated field");
    require(view.plainText().contains(QStringLiteral("Field 0: 0")), "all export retains filtered large result data");
    view.setDocument(PropertyDocument());
    require(tree->topLevelItemCount() == 0 && view.plainText().isEmpty(), "empty async update clears old property values");
    std::cout << "PASS: " << checks << " native property view checks; no clipboard writes\n";
    return 0;
}
