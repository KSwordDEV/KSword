#include "FieldTreePresenter.h"
#include "../Internationalization/LanguageManager.h"
#include "../theme.h"
#include <QAbstractItemView>
#include <QApplication>
#include <QClipboard>
#include <QKeyEvent>
#include <QMenu>
#include <QPointer>
#include <QTreeWidget>
#include <functional>

namespace
{
    constexpr const char* authorityProperty = "ksword_structured_copy_authority";
    // 行序来自模型，字段树和表格的两列统一用冒号；其他列数仍保留制表符。
    QString rowText(const QAbstractItemModel* model, const QModelIndex& index)
    {
        QStringList values;
        const int count = model->columnCount(index.parent());
        for (int column = 0; column < count; ++column)
            values.append(model->index(index.row(), column, index.parent()).data().toString());
        if (count == 2)
            return values.at(1).isEmpty() ? values.at(0) : QStringLiteral("%1: %2").arg(values.at(0), values.at(1));
        return values.join(QLatin1Char('\t'));
    }

    // 按模型遍历冻结字符串；此处没有事件循环，不保存跨刷新使用的 QModelIndex。
    QString modelText(const QAbstractItemModel* model)
    {
        QStringList lines;
        std::function<void(const QModelIndex&)> append = [&](const QModelIndex& parent)
        {
            for (int row = 0; row < model->rowCount(parent); ++row)
            {
                const QModelIndex index = model->index(row, 0, parent);
                lines.append(rowText(model, index));
                append(index);
            }
        };
        append(QModelIndex());
        return lines.join(QLatin1Char('\n'));
    }

    // 键盘与工具栏共用相同复制序列化器；过滤器只在明确 Ctrl+C 时写剪贴板。
    class StructuredCopyKeys final : public QObject
    {
    public:
        explicit StructuredCopyKeys(QAbstractItemView* view) : QObject(view), m_view(view)
        {
            view->installEventFilter(this);
        }
        bool eventFilter(QObject* source, QEvent* event) override
        {
            if (source == m_view && (event->type() == QEvent::ShortcutOverride || event->type() == QEvent::KeyPress))
            {
                const auto* key = static_cast<QKeyEvent*>(event);
                if (key->matches(QKeySequence::Copy))
                {
                    event->accept();
                    if (event->type() == QEvent::KeyPress)
                    {
                        const QString payload = ks::ui::StructuredCopyText(m_view);
                        if (!payload.isEmpty()) QApplication::clipboard()->setText(payload);
                    }
                    return true;
                }
            }
            return QObject::eventFilter(source, event);
        }
    private:
        QPointer<QAbstractItemView> m_view; // 只在宿主仍存活时处理快捷键。
    };
}

namespace ks::ui
{
    QString FieldTreeToPlainText(const QTreeWidget* tree)
    {
        if (tree == nullptr) return {};
        QString text;
        // 显式角色区分报告分组和 JSON/XML 容器；不得因节点有孩子就改变其含义。
        std::function<void(const QTreeWidgetItem*, int)> append = [&](const QTreeWidgetItem* item, const int depth)
        {
            const bool group = item->data(0, Qt::UserRole + 913).toBool();
            const QString padding(depth * 2, QLatin1Char(' '));
            if (group)
                text += QStringLiteral("[%1]%2\n").arg(item->text(0), item->text(1).isEmpty()
                    ? QString() : QLatin1Char(' ') + item->text(1));
            else
                text += padding + (item->text(1).isEmpty() ? item->text(0)
                    : QStringLiteral("%1: %2").arg(item->text(0), item->text(1))) + QLatin1Char('\n');
            for (int index = 0; index < item->childCount(); ++index) append(item->child(index), depth + 1);
            if (group) text += QLatin1Char('\n');
        };
        for (int index = 0; index < tree->topLevelItemCount(); ++index) append(tree->topLevelItem(index), 0);
        return text;
    }

    StructuredCopySnapshot CaptureStructuredCopy(const QAbstractItemView* view, const QModelIndex& clicked)
    {
        StructuredCopySnapshot snapshot;
        if (view == nullptr || view->model() == nullptr) return snapshot;
        const QAbstractItemModel* model = view->model();
        snapshot.hasRow = clicked.isValid() && clicked.model() == model;
        if (snapshot.hasRow)
        {
            const QModelIndex value = model->columnCount(clicked.parent()) == 2
                ? clicked.siblingAtColumn(1) : clicked;
            snapshot.value = value.data().toString();
            snapshot.row = rowText(model, clicked);
        }
        const QVariant authority = view->property(authorityProperty);
        const auto* tree = qobject_cast<const QTreeWidget*>(view);
        snapshot.all = authority.isValid() ? authority.toString()
            : tree != nullptr ? FieldTreeToPlainText(tree) : modelText(model);
        return snapshot;
    }

    QString StructuredSelectionText(const QAbstractItemView* view)
    {
        if (view == nullptr || view->model() == nullptr || view->selectionModel() == nullptr) return {};
        const QAbstractItemModel* model = view->model();
        const auto* selection = view->selectionModel();
        QStringList lines;
        // SelectRows 是统一契约，但亦支持调用方仅选任一列的情形，避免一行复制两次。
        std::function<void(const QModelIndex&)> append = [&](const QModelIndex& parent)
        {
            for (int row = 0; row < model->rowCount(parent); ++row)
            {
                const QModelIndex index = model->index(row, 0, parent);
                bool selected = false;
                for (int column = 0; column < model->columnCount(parent); ++column)
                    selected = selected || selection->isSelected(index.siblingAtColumn(column));
                if (selected) lines.append(rowText(model, index));
                append(index);
            }
        };
        append(QModelIndex());
        return lines.join(QLatin1Char('\n'));
    }

    void SetStructuredCopyFallback(QAbstractItemView* view, const QString& authoritativeText)
    {
        if (view != nullptr) view->setProperty(authorityProperty, authoritativeText);
    }

    QString StructuredCopyText(const QAbstractItemView* view)
    {
        const QString selection = StructuredSelectionText(view);
        return selection.isEmpty() ? CaptureStructuredCopy(view, {}).all : selection;
    }

    QString ExecStructuredCopyMenu(QAbstractItemView* view, const QPoint& localPosition)
    {
        if (view == nullptr || view->model() == nullptr) return {};
        const QModelIndex clicked = view->indexAt(localPosition);
        const StructuredCopySnapshot frozen = CaptureStructuredCopy(view, clicked);
        const QPoint global = view->viewport()->mapToGlobal(localPosition);
        const QPointer<QAbstractItemView> ownerGuard(view);
        // 堆上菜单由宿主接管，避免父销毁时删除栈菜单；退出后同时核对两个生命周期。
        auto* menu = new QMenu(view);
        const QPointer<QMenu> menuGuard(menu);
        menu->setStyleSheet(KswordTheme::ContextMenuStyle());
        QAction* value = menu->addAction(ks::i18n::displayText(QStringLiteral("复制该值")));
        QAction* row = menu->addAction(ks::i18n::displayText(QStringLiteral("复制该行")));
        QAction* all = menu->addAction(ks::i18n::displayText(QStringLiteral("复制全部")));
        value->setEnabled(frozen.hasRow && !frozen.value.isEmpty());
        row->setEnabled(frozen.hasRow);
        const QAction* selected = menu->exec(global);
        if (!ownerGuard || !menuGuard) return {};
        // 这里比较 action 身份和冻结字符串，不再解引用旧 item/index/model。
        const QString result = selected == value ? frozen.value : selected == row ? frozen.row
            : selected == all ? frozen.all : QString();
        menu->deleteLater();
        return result;
    }

    void InstallStructuredCopyMenu(QAbstractItemView* view)
    {
        if (view == nullptr || view->property("ksword_structured_copy_managed").toBool()) return;
        view->setProperty("ksword_structured_copy_managed", true);
        view->setContextMenuPolicy(Qt::CustomContextMenu);
        new StructuredCopyKeys(view);
        QObject::connect(view, &QAbstractItemView::customContextMenuRequested, view,
            [view](const QPoint& position)
            {
                const QPointer<QAbstractItemView> guard(view);
                const QString payload = ExecStructuredCopyMenu(view, position);
                if (guard && !payload.isEmpty()) QApplication::clipboard()->setText(payload);
            });
    }
}
