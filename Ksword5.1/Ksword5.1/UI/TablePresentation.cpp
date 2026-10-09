#include "TablePresentation.h"
#include "VisibleTableWidget.h"

#include <QApplication>
#include <QEvent>
#include <QFrame>
#include <QHeaderView>
#include <QPointer>
#include <QTableView>
#include <QTimer>
#include <QTreeView>
#include <QVariant>

namespace
{
    constexpr char kBegin[] = "/*KSWORD_TABLE_PRESENTATION_BEGIN*/";
    constexpr char kEnd[] = "/*KSWORD_TABLE_PRESENTATION_END*/";
    constexpr char kPreserve[] = "ksword_preserve_custom_table_presentation";
    constexpr char kDensity[] = "ksword_table_presentation_density";
    constexpr char kNormalizeHeader[] = "ksword_table_presentation_normalize_header";
    constexpr char kOriginalFrame[] = "ksword_table_presentation_original_frame";
    constexpr char kOriginalGrid[] = "ksword_table_presentation_original_grid";
    constexpr char kPending[] = "ksword_table_presentation_pending";
    constexpr char kInstalled[] = "ksword_table_presentation_installed";

    QString withoutPresentationBlock(QString style)
    {
        const qsizetype begin = style.indexOf(QLatin1String(kBegin));
        if (begin >= 0)
        {
            const qsizetype end = style.indexOf(QLatin1String(kEnd), begin);
            if (end >= 0) style.remove(begin, end + qstrlen(kEnd) - begin);
        }
        return style;
    }

    void replacePresentationBlock(QWidget* widget, const QString& block)
    {
        if (widget == nullptr) return;
        QString style = withoutPresentationBlock(widget->styleSheet());
        if (!block.isEmpty()) style += QLatin1String(kBegin) + block + QLatin1String(kEnd);
        if (style != widget->styleSheet()) widget->setStyleSheet(style);
    }

    QHeaderView* columnHeader(QAbstractItemView* view)
    {
        if (auto* table = qobject_cast<QTableView*>(view)) return table->horizontalHeader();
        if (auto* tree = qobject_cast<QTreeView*>(view)) return tree->header();
        return nullptr;
    }

    const QHeaderView* columnHeader(const QAbstractItemView* view)
    {
        if (const auto* table = qobject_cast<const QTableView*>(view)) return table->horizontalHeader();
        if (const auto* tree = qobject_cast<const QTreeView*>(view)) return tree->header();
        return nullptr;
    }

    bool supportedView(const QAbstractItemView* view)
    {
        return qobject_cast<const QTableView*>(view) != nullptr || qobject_cast<const QTreeView*>(view) != nullptr;
    }

    void schedulePresentation(QAbstractItemView* view)
    {
        if (!supportedView(view) || view->property(kPending).toBool()) return;
        view->setProperty(kPending, true);
        const QPointer<QAbstractItemView> guardedView(view);
        QTimer::singleShot(0, view, [guardedView]()
        {
            if (guardedView.isNull()) return;
            guardedView->setProperty(kPending, false);
            const QVariant normalize = guardedView->property(kNormalizeHeader);
            ks::ui::ApplyTablePresentation(guardedView.data(), !normalize.isValid() || normalize.toBool());
        });
    }

    class TablePresentationFilter final : public QObject
    {
    public:
        explicit TablePresentationFilter(QObject* parent) : QObject(parent) {}

        bool eventFilter(QObject* source, QEvent* event) override
        {
            if (event == nullptr) return false;
            switch (event->type())
            {
            case QEvent::Polish:
            case QEvent::Show:
            case QEvent::StyleChange:
            case QEvent::FontChange:
            case QEvent::PaletteChange:
            case QEvent::ApplicationPaletteChange:
                // Only the view itself, never header/viewport/popup Show/Resize internals.
                schedulePresentation(qobject_cast<QAbstractItemView*>(source));
                break;
            default:
                break;
            }
            return false;
        }
    };
}

namespace ks::ui
{
    bool PreservesCustomTablePresentation(const QAbstractItemView* view)
    {
        return view != nullptr && (view->property(kPreserve).toBool()
            || view->property("ks_preserve_table_presentation").toBool());
    }

    void SetPreserveCustomTablePresentation(QAbstractItemView* view, const bool preserve)
    {
        if (view == nullptr) return;
        view->setProperty(kPreserve, preserve);
        const QVariant normalize = view->property(kNormalizeHeader);
        ApplyTablePresentation(view, !normalize.isValid() || normalize.toBool());
    }

    void SetTablePresentationDensity(QAbstractItemView* view, const TablePresentationDensity density)
    {
        if (view == nullptr) return;
        view->setProperty(kDensity, static_cast<int>(density));
        const QVariant normalize = view->property(kNormalizeHeader);
        ApplyTablePresentation(view, !normalize.isValid() || normalize.toBool());
    }

    void CopyTablePresentation(const QAbstractItemView* source, QAbstractItemView* target)
    {
        if (!supportedView(source) || !supportedView(target) || source == target) return;
        target->setProperty(kDensity, source->property(kDensity));
        target->setProperty(kPreserve, PreservesCustomTablePresentation(source));
        const auto* sourceTable = qobject_cast<const QTableView*>(source);
        auto* targetTable = qobject_cast<QTableView*>(target);
        const QVariant normalize = source->property(kNormalizeHeader);
        const bool preserveHeader = (sourceTable != nullptr && PreservesCustomTableHeaderStyle(sourceTable))
            || (normalize.isValid() && !normalize.toBool());
        if (targetTable != nullptr) SetPreserveCustomTableHeaderStyle(targetTable, preserveHeader);
        if (PreservesCustomTablePresentation(source) && sourceTable != nullptr && targetTable != nullptr)
        {
            targetTable->setProperty(kOriginalGrid, sourceTable->showGrid());
            targetTable->setShowGrid(sourceTable->showGrid());
        }
        if (PreservesCustomTablePresentation(source))
        {
            target->setProperty(kOriginalFrame, static_cast<int>(source->frameShape()));
            target->setFrameShape(source->frameShape());
            target->setStyleSheet(source->styleSheet());
        }
        if (PreservesCustomTablePresentation(source) || preserveHeader || (normalize.isValid() && !normalize.toBool()))
        {
            if (const QHeaderView* sourceHeader = columnHeader(source))
                if (QHeaderView* targetHeader = columnHeader(target)) targetHeader->setStyleSheet(sourceHeader->styleSheet());
            if (sourceTable != nullptr && targetTable != nullptr)
                targetTable->verticalHeader()->setStyleSheet(sourceTable->verticalHeader()->styleSheet());
        }
        ApplyTablePresentation(target, !normalize.isValid() || normalize.toBool());
    }

    void ApplyTablePresentation(QAbstractItemView* view, const bool normalizeHeader)
    {
        if (!supportedView(view)) return;
        view->setProperty(kNormalizeHeader, normalizeHeader);
        auto* table = qobject_cast<QTableView*>(view);
        if (PreservesCustomTablePresentation(view))
        {
            replacePresentationBlock(view, {});
            replacePresentationBlock(columnHeader(view), {});
            if (table != nullptr) replacePresentationBlock(table->verticalHeader(), {});
            if (view->property(kOriginalFrame).isValid())
                view->setFrameShape(static_cast<QFrame::Shape>(view->property(kOriginalFrame).toInt()));
            if (table != nullptr && table->property(kOriginalGrid).isValid())
                table->setShowGrid(table->property(kOriginalGrid).toBool());
            return;
        }

        // Never replace the delegate: semantic brushes, search marks, virtualized painting,
        // custom row heights, alternating-row policy and current selection remain business-owned.
        if (!view->property(kOriginalFrame).isValid()) view->setProperty(kOriginalFrame, static_cast<int>(view->frameShape()));
        if (table != nullptr && !table->property(kOriginalGrid).isValid()) table->setProperty(kOriginalGrid, table->showGrid());
        if (view->frameShape() != QFrame::NoFrame) view->setFrameShape(QFrame::NoFrame);
        if (table != nullptr && table->showGrid()) table->setShowGrid(false);
        const bool compact = view->property(kDensity).toInt() == static_cast<int>(TablePresentationDensity::Compact);
        const QString cellPadding = compact ? QStringLiteral("2px 6px") : QStringLiteral("4px 8px");
        const QString headerPadding = compact ? QStringLiteral("3px 6px") : QStringLiteral("5px 8px");
        replacePresentationBlock(view, QStringLiteral(
            "QTableView,QTableWidget,QTreeView,QTreeWidget{"
            "border:0;border-radius:0;color:palette(text);"
            "alternate-background-color:palette(alternate-base);"
            "selection-background-color:palette(highlight);selection-color:palette(highlighted-text);}"
            "QTableView::item,QTableWidget::item,QTreeView::item,QTreeWidget::item{border:0;padding:%1;}"
            "QTableCornerButton::section{background:transparent;border:0;}")
            .arg(cellPadding));

        // normalizeHeader=false and the existing header-specific opt-out retain custom geometry.
        if (!normalizeHeader || (table != nullptr && PreservesCustomTableHeaderStyle(table)))
        {
            replacePresentationBlock(columnHeader(view), {});
            if (table != nullptr) replacePresentationBlock(table->verticalHeader(), {});
            return;
        }
        const QString headerBlock = QStringLiteral(
            "QHeaderView{background:transparent;border:0;}"
            "QHeaderView::section{background-color:palette(base);color:palette(text);"
            "border:0;border-bottom:1px solid palette(mid);padding:%1;font-weight:400;}"
            "QHeaderView::section:hover{background-color:palette(alternate-base);}")
            .arg(headerPadding);
        replacePresentationBlock(columnHeader(view), headerBlock);
        if (table != nullptr)
        {
            replacePresentationBlock(table->verticalHeader(), QStringLiteral(
                "QHeaderView{background:transparent;border:0;}"
                "QHeaderView::section{background:transparent;color:palette(text);border:0;"
                "padding:%1;font-weight:400;}").arg(headerPadding));
        }
    }

    void InstallGlobalTablePresentation(QApplication* appInstance)
    {
        if (appInstance == nullptr || appInstance->property(kInstalled).toBool()) return;
        appInstance->setProperty(kInstalled, true);
        auto* filter = new TablePresentationFilter(appInstance);
        appInstance->installEventFilter(filter);
        for (QWidget* widget : appInstance->allWidgets())
            schedulePresentation(qobject_cast<QAbstractItemView*>(widget));
    }
}
