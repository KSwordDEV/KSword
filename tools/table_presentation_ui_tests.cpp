// Actual production presentation, Qt offscreen only. No driver/process enumeration/clipboard.
#include "../Ksword5.1/Ksword5.1/UI/TablePresentation.h"
#include "../Ksword5.1/Ksword5.1/UI/GlobalUiBaseStyle.h"
#include "../Ksword5.1/Ksword5.1/UI/VisibleTableWidget.h"
#include "../Ksword5.1/Ksword5.1/theme.h"

#include <QApplication>
#include <QDir>
#include <QFont>
#include <QHeaderView>
#include <QLabel>
#include <QListView>
#include <QPointer>
#include <QStandardItemModel>
#include <QStyledItemDelegate>
#include <QTableWidget>
#include <QTreeWidget>
#include <QVBoxLayout>

#include <cstdio>

namespace
{
    int checks = 0;
    int failures = 0;
    void expect(const bool condition, const char* label)
    {
        ++checks;
        if (!condition) { ++failures; std::printf("TABLE_PRESENTATION_FAILURE=%s\n", label); }
    }
    void drain()
    {
        for (int iteration = 0; iteration < 12; ++iteration)
        {
            QCoreApplication::sendPostedEvents();
            QCoreApplication::processEvents();
        }
    }
    QPalette themePalette(const bool dark)
    {
        KswordTheme::SetDarkModeEnabled(dark);
        QPalette palette;
        palette.setColor(QPalette::Window, KswordTheme::MainBackgroundColor());
        palette.setColor(QPalette::WindowText, KswordTheme::TextPrimaryColor());
        palette.setColor(QPalette::Base, KswordTheme::SurfaceColor());
        palette.setColor(QPalette::AlternateBase, KswordTheme::SurfaceAltColor());
        palette.setColor(QPalette::Button, KswordTheme::SurfaceAltColor());
        palette.setColor(QPalette::ButtonText, KswordTheme::TextPrimaryColor());
        palette.setColor(QPalette::Text, KswordTheme::TextPrimaryColor());
        palette.setColor(QPalette::PlaceholderText, KswordTheme::TextSecondaryColor());
        palette.setColor(QPalette::Highlight, KswordTheme::ControlAccentColor());
        palette.setColor(QPalette::HighlightedText, KswordTheme::OnAccentColor(KswordTheme::ControlAccentColor()));
        palette.setColor(QPalette::Mid, KswordTheme::BorderColor());
        palette.setColor(QPalette::Midlight, KswordTheme::BorderStrongColor());
        palette.setColor(QPalette::Disabled, QPalette::Text, KswordTheme::TextDisabledColor());
        return palette;
    }
    void applyTheme(QApplication& app, const bool dark)
    {
        app.setPalette(themePalette(dark));
        app.setStyleSheet(ks::ui::BuildGlobalBaseControlStyleBlock());
        drain();
    }
    void checkViewContracts(QApplication& app, const QString& output)
    {
        QWidget root;
        auto* layout = new QVBoxLayout(&root);
        layout->setContentsMargins(20, 18, 20, 18);
        layout->setSpacing(12);
        auto* title = new QLabel(QStringLiteral("Shared table presentation | inert sample data"), &root);
        layout->addWidget(title);
        auto* table = new QTableWidget(4, 4, &root);
        table->setHorizontalHeaderLabels({QStringLiteral("Process"), QStringLiteral("PID"),
            QStringLiteral("State"), QStringLiteral("Location")});
        table->verticalHeader()->hide();
        table->horizontalHeader()->setStretchLastSection(true);
        table->setColumnWidth(0, 175);
        table->setColumnWidth(1, 80);
        table->setColumnWidth(2, 150);
        table->setSelectionBehavior(QAbstractItemView::SelectRows);
        table->setSelectionMode(QAbstractItemView::ExtendedSelection);
        table->setAlternatingRowColors(true);
        table->setStyleSheet(QStringLiteral("QTableWidget{border:2px solid red;} QLabel{font-style:italic;}"));
        const QStringList names{QStringLiteral("KSword.exe"), QStringLiteral("services.exe"),
            QStringLiteral("explorer.exe"), QStringLiteral("sample-helper.exe")};
        for (int row = 0; row < table->rowCount(); ++row)
        {
            table->setItem(row, 0, new QTableWidgetItem(names[row]));
            table->setItem(row, 1, new QTableWidgetItem(QString::number(1000 + row * 10)));
            table->setItem(row, 2, new QTableWidgetItem(row == 3 ? QStringLiteral("Unavailable") : QStringLiteral("Running")));
            table->setItem(row, 3, new QTableWidgetItem(QStringLiteral("C:\\Windows\\System32\\sample.exe")));
        }
        table->item(3, 2)->setForeground(QColor(194, 112, 24));
        table->setRowHeight(2, 44);
        auto* delegate = new QStyledItemDelegate(table);
        table->setItemDelegate(delegate);
        layout->addWidget(table, 1);
        auto* tree = new QTreeWidget(&root);
        tree->setHeaderLabels({QStringLiteral("Property"), QStringLiteral("Value")});
        tree->setAlternatingRowColors(false);
        tree->setSelectionMode(QAbstractItemView::ExtendedSelection);
        tree->setColumnWidth(0, 255);
        auto* group = new QTreeWidgetItem(tree, {QStringLiteral("Identity")});
        new QTreeWidgetItem(group, {QStringLiteral("Image"), QStringLiteral("KSword.exe")});
        new QTreeWidgetItem(group, {QStringLiteral("File object"), QStringLiteral("0xFFFF9FBE10A80120")});
        group->setExpanded(true);
        layout->addWidget(tree, 1);
        root.resize(920, 530);
        root.show();
        table->selectRow(0);
        drain();
        expect(!table->showGrid() && table->frameShape() == QFrame::NoFrame, "grid and outer frame removed");
        expect(tree->frameShape() == QFrame::NoFrame, "tree outer frame removed");
        expect(table->alternatingRowColors() && !tree->alternatingRowColors(), "existing alternate-row policies retained");
        expect(table->itemDelegate() == delegate, "custom delegate retained");
        expect(table->rowHeight(2) == 44, "custom row height retained");
        expect(table->selectionMode() == QAbstractItemView::ExtendedSelection, "multiple selection retained");
        expect(table->styleSheet().contains(QStringLiteral("QLabel{font-style:italic;}")), "unrelated local rules retained");
        expect(group->isExpanded() && tree->topLevelItem(0) == group, "tree hierarchy and expansion retained");
        expect(table->item(3, 2)->foreground().color() == QColor(194, 112, 24), "semantic item foreground retained");
        expect(table->horizontalHeader()->font().weight() == QFont::Normal, "header weight normal");
        expect(table->horizontalHeader()->styleSheet().contains(QStringLiteral("border-bottom:1px"))
            && !table->horizontalHeader()->styleSheet().contains(QStringLiteral("border-right:")), "header has only horizontal separator");
        const QString firstStyle = table->styleSheet();
        ks::ui::ApplyTablePresentation(table);
        drain();
        expect(table->styleSheet() == firstStyle, "repeated application is idempotent");

        for (const bool dark : {false, true, false})
        {
            applyTheme(app, dark);
            expect(table->palette().color(QPalette::Text) == app.palette().color(QPalette::Text), "table follows hot theme text");
            expect(tree->palette().color(QPalette::Base) == app.palette().color(QPalette::Base), "tree follows hot theme background");
            expect(table->selectionModel()->isRowSelected(0, {}), "hot theme preserves selection");
            expect(table->itemDelegate() == delegate && group->isExpanded(), "hot theme preserves delegate and expansion");
            expect(table->styleSheet().count(QStringLiteral("KSWORD_TABLE_PRESENTATION_BEGIN")) == 1, "hot theme does not append duplicate blocks");
            const QImage header = table->horizontalHeader()->grab().toImage();
            const int boundary = table->columnWidth(0);
            expect(header.pixelColor(boundary - 1, 3) == header.pixelColor(boundary + 1, 3), "rendered header has no vertical section line");
            const QImage viewport = table->viewport()->grab().toImage();
            const int emptyCellPixel = table->columnWidth(0) + table->columnWidth(1) + table->columnWidth(2) - 12;
            const QColor paintedHighlight = viewport.pixelColor(emptyCellPixel, table->rowHeight(0) / 2);
            // The contrast-adjusted token may use floating RGB; a rendered pixel is 8-bit RGBA.
            expect(paintedHighlight.rgba() == table->palette().color(QPalette::Highlight).rgba(), "selected row paints current theme highlight");
            if (!output.isEmpty())
            {
                expect(root.grab().save(QDir(output).filePath(dark
                    ? QStringLiteral("shared-tables-dark.png") : QStringLiteral("shared-tables-light.png"))), "sample screenshot saved");
            }
        }
        ks::ui::SetTablePresentationDensity(table, ks::ui::TablePresentationDensity::Compact);
        drain();
        expect(table->styleSheet().contains(QStringLiteral("padding:2px 6px")), "compact density uses shared cell spacing");
        expect(table->rowHeight(2) == 44, "density preserves custom row height");
        tree->header()->hide();
        ks::ui::ApplyTablePresentation(tree);
        drain();
        expect(tree->header()->isHidden(), "presentation preserves hidden header");
    }
    void checkExceptions()
    {
        QTableWidget custom(2, 2);
        custom.setShowGrid(true);
        custom.setFrameShape(QFrame::Box);
        const QString customStyle = QStringLiteral("QTableWidget{border:3px solid teal;} QTableWidget::item{padding:0;}");
        custom.setStyleSheet(customStyle);
        const QString headerStyle = QStringLiteral("QHeaderView::section{padding:0;font-weight:700;border:1px solid teal;}");
        custom.horizontalHeader()->setStyleSheet(headerStyle);
        ks::ui::SetPreserveCustomTablePresentation(&custom, true);
        custom.show();
        drain();
        expect(custom.showGrid() && custom.frameShape() == QFrame::Box, "full opt-out preserves specialized grid/frame");
        expect(custom.styleSheet() == customStyle && custom.horizontalHeader()->styleSheet() == headerStyle, "full opt-out preserves specialized QSS");
        ks::ui::SetPreserveCustomTablePresentation(&custom, false);
        drain();
        expect(!custom.showGrid() && custom.frameShape() == QFrame::NoFrame, "opt-in restores shared presentation");
        ks::ui::SetPreserveCustomTablePresentation(&custom, true);
        drain();
        expect(custom.showGrid() && custom.frameShape() == QFrame::Box, "late opt-out restores original grid/frame");
        expect(custom.styleSheet() == customStyle && custom.horizontalHeader()->styleSheet() == headerStyle, "late opt-out removes only owned blocks");

        QTableWidget headerOnly(2, 2);
        headerOnly.horizontalHeader()->setStyleSheet(headerStyle);
        ks::ui::SetPreserveCustomTableHeaderStyle(&headerOnly, true);
        headerOnly.show();
        drain();
        expect(!headerOnly.showGrid() && headerOnly.frameShape() == QFrame::NoFrame, "header-only opt-out retains shared body");
        expect(headerOnly.horizontalHeader()->styleSheet() == headerStyle, "existing header opt-out remains supported");

        QTableWidget capability(2, 2);
        capability.horizontalHeader()->setStyleSheet(headerStyle);
        ks::ui::ApplyTablePresentation(&capability, false);
        capability.show();
        drain();
        ks::ui::SetTablePresentationDensity(&capability, ks::ui::TablePresentationDensity::Compact);
        drain();
        expect(capability.horizontalHeader()->styleSheet() == headerStyle, "normalizeHeader false survives global discovery and density changes");

        QTableWidget mirror(2, 2);
        ks::ui::CopyTablePresentation(&capability, &mirror);
        mirror.show();
        drain();
        expect(mirror.styleSheet().contains(QStringLiteral("padding:2px 6px")), "mirrored view retains source density");
        expect(mirror.horizontalHeader()->styleSheet() == headerStyle, "mirrored view retains custom source header");
        ks::ui::CopyTablePresentation(&custom, &mirror);
        drain();
        expect(ks::ui::PreservesCustomTablePresentation(&mirror) && mirror.styleSheet() == customStyle,
            "mirrored specialized view retains complete opt-out and QSS");
        expect(mirror.showGrid() == custom.showGrid(), "mirrored specialized view retains source grid");
        expect(mirror.frameShape() == custom.frameShape(), "mirrored specialized view retains source frame");

        QListView list;
        const QFrame::Shape originalShape = list.frameShape();
        ks::ui::ApplyTablePresentation(&list);
        expect(list.styleSheet().isEmpty() && list.frameShape() == originalShape, "unsupported list/popup views untouched");
    }
    void checkLifetime()
    {
        for (int iteration = 0; iteration < 100; ++iteration)
        {
            auto* root = new QWidget;
            auto* table = new QTableWidget(2, 2, root);
            auto* tree = new QTreeWidget(root);
            root->show();
            const QPointer<QTableWidget> tableGuard(table);
            const QPointer<QTreeWidget> treeGuard(tree);
            delete root; // queued Show discovery must not dereference the deleted subtree.
            drain();
            expect(tableGuard.isNull() && treeGuard.isNull(), "queued discovery is safe after subtree destruction");
        }
    }
}

int main(int argc, char* argv[])
{
    QApplication app(argc, argv);
    app.setStyle(QStringLiteral("Fusion"));
    app.setFont(QFont(QStringLiteral("Segoe UI"), 10));
    const QString output = argc > 1 ? QString::fromLocal8Bit(argv[1]) : QString();
    if (!output.isEmpty()) QDir().mkpath(output);
    applyTheme(app, false);
    ks::ui::InstallGlobalTablePresentation(&app);
    ks::ui::InstallGlobalTablePresentation(&app);
    checkViewContracts(app, output);
    checkExceptions();
    checkLifetime();
    std::printf("TABLE_PRESENTATION_CHECKS=%d\nTABLE_PRESENTATION_FAILURES=%d\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
