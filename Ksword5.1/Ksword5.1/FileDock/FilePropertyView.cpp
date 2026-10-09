#include "FilePropertyView.h"
#include "../Internationalization/LanguageManager.h"

#include <QApplication>
#include <QClipboard>
#include <QComboBox>
#include <QEvent>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QPainter>
#include <QPointer>
#include <QResizeEvent>
#include <QScrollBar>
#include <QSet>
#include <QShortcut>
#include <QSignalBlocker>
#include <QStyle>
#include <QStyledItemDelegate>
#include <QTextLayout>
#include <QTextOption>
#include <QTimer>
#include <QToolButton>
#include <QTreeWidget>
#include <QVBoxLayout>
#include <QtMath>

#include <algorithm>
#include <functional>

namespace file_dock_detail
{
    namespace
    {
        enum PropertyRole { KindRole = Qt::UserRole + 176, KeyRole, RowRole, ValueRole };

        FilePropertyView::Presentation& sessionPresentation()
        {
            static auto presentation = FilePropertyView::Presentation::Sections;
            return presentation;
        }

        QString translated(const QString& source)
        {
            return ks::i18n::sourceText(source);
        }

        void appendText(const PropertyNode& node, QStringList& lines, const int depth,
            const bool localize)
        {
            const auto name = localize ? translated(node.name) : node.name;
            const auto value = localize && node.translateValue ? translated(node.value) : node.value;
            const QString indentation(depth * 2, QLatin1Char(' '));
            if (node.kind == PropertyNode::Kind::Section)
                lines.append(indentation + QLatin1Char('[') + name + QLatin1Char(']'));
            else if (node.kind == PropertyNode::Kind::Note)
                lines.append(indentation + (localize ? translated(node.value) : node.value));
            else
                lines.append(indentation + name + QStringLiteral(": ") + value);
            for (const auto& child : node.children)
                appendText(child, lines, depth + (node.kind == PropertyNode::Kind::Field ? 1 : 0), localize);
        }

        void walkItems(QTreeWidgetItem* parent,
            const std::function<void(QTreeWidgetItem*)>& visitor)
        {
            for (int index = 0; index < parent->childCount(); ++index)
            {
                auto* item = parent->child(index);
                visitor(item);
                walkItems(item, visitor);
            }
        }

        // QTextLayout is only the native delegate's plain text glyph layout.
        // There is no text document, rich text engine, editor or per-row widget.
        qreal layoutPlainText(const QString& text, const QFont& font, const qreal width,
            QPainter* painter = nullptr, const QPointF& origin = QPointF())
        {
            qreal height = 0;
            const qreal available = std::max<qreal>(24, width);
            const auto paragraphs = text.split(QLatin1Char('\n'));
            for (const auto& paragraph : paragraphs)
            {
                QTextLayout layout(paragraph, font);
                QTextOption option;
                option.setWrapMode(QTextOption::WrapAtWordBoundaryOrAnywhere);
                layout.setTextOption(option);
                layout.beginLayout();
                for (;;)
                {
                    QTextLine line = layout.createLine();
                    if (!line.isValid()) break;
                    line.setLineWidth(available);
                    line.setPosition(QPointF(0, height));
                    height += line.height();
                }
                layout.endLayout();
                if (paragraph.isEmpty()) height += QFontMetricsF(font).height();
                if (painter) layout.draw(painter, origin);
            }
            return height;
        }

        class PropertyDelegate final : public QStyledItemDelegate
        {
        public:
            explicit PropertyDelegate(QTreeWidget* tree) : QStyledItemDelegate(tree), m_tree(tree) {}
            bool sections = true;

            void paint(QPainter* painter, const QStyleOptionViewItem& supplied,
                const QModelIndex& index) const override
            {
                QStyleOptionViewItem option(supplied);
                initStyleOption(&option, index);
                const auto kind = static_cast<PropertyNode::Kind>(index.data(KindRole).toInt());
                const bool section = kind == PropertyNode::Kind::Section;
                const bool selected = option.state.testFlag(QStyle::State_Selected);
                const auto text = option.text;
                option.text.clear();
                if (section && !selected) option.backgroundBrush = option.palette.brush(QPalette::AlternateBase);
                const QWidget* widget = option.widget;
                auto* style = widget ? widget->style() : QApplication::style();
                style->drawControl(QStyle::CE_ItemViewItem, &option, painter, widget);
                QFont font = option.font;
                if (section) font.setBold(true);
                const int insetX = sections ? 10 : 6;
                const int insetY = section ? 9 : (sections ? 7 : 4);
                const QRect area = option.rect.adjusted(insetX, insetY, -insetX, -insetY);
                painter->save();
                painter->setClipRect(option.rect);
                const auto group = option.state.testFlag(QStyle::State_Enabled)
                    ? (option.state.testFlag(QStyle::State_Active) ? QPalette::Active : QPalette::Inactive)
                    : QPalette::Disabled;
                painter->setPen(option.palette.color(group, selected ? QPalette::HighlightedText : QPalette::Text));
                layoutPlainText(text, font, area.width(), painter, area.topLeft());
                if (section && !selected)
                {
                    painter->setPen(option.palette.color(group, QPalette::Mid));
                    painter->drawLine(option.rect.bottomLeft(), option.rect.bottomRight());
                }
                painter->restore();
            }

            QSize sizeHint(const QStyleOptionViewItem& supplied, const QModelIndex& index) const override
            {
                QStyleOptionViewItem option(supplied);
                initStyleOption(&option, index);
                const auto kind = static_cast<PropertyNode::Kind>(index.data(KindRole).toInt());
                const bool span = kind != PropertyNode::Kind::Field;
                QFont font = option.font;
                if (kind == PropertyNode::Kind::Section) font.setBold(true);
                int width = m_tree->columnWidth(index.column());
                if (span && index.column() == 0)
                    width = m_tree->viewport()->width();
                if (index.column() == 0)
                {
                    int depth = m_tree->rootIsDecorated() ? 1 : 0;
                    for (auto ancestor = index.parent(); ancestor.isValid(); ancestor = ancestor.parent()) ++depth;
                    width -= depth * m_tree->indentation();
                }
                const int insetX = sections ? 10 : 6;
                const int insetY = kind == PropertyNode::Kind::Section ? 9 : (sections ? 7 : 4);
                const int height = qCeil(layoutPlainText(option.text, font, width - 2 * insetX)) + 2 * insetY;
                return QSize(std::max(24, width), std::max(height, QFontMetrics(font).height() + 2 * insetY));
            }

        private:
            QTreeWidget* m_tree;
        };
    }

    PropertyDocument& PropertyDocument::section(const QString& title)
    {
        PropertyNode node;
        node.kind = PropertyNode::Kind::Section;
        node.name = title;
        nodes.append(node);
        return *this;
    }

    PropertyDocument& PropertyDocument::field(const QString& name, const QString& value,
        const bool translateValue)
    {
        PropertyNode node;
        node.kind = PropertyNode::Kind::Field;
        node.name = name;
        node.value = value;
        node.translateValue = translateValue;
        if (!nodes.isEmpty() && nodes.last().kind == PropertyNode::Kind::Section)
            nodes.last().children.append(node);
        else nodes.append(node);
        return *this;
    }

    PropertyDocument& PropertyDocument::note(const QString& body)
    {
        PropertyNode node;
        node.kind = PropertyNode::Kind::Note;
        node.value = body;
        if (!nodes.isEmpty() && nodes.last().kind == PropertyNode::Kind::Section)
            nodes.last().children.append(node);
        else nodes.append(node);
        return *this;
    }

    QString PropertyDocument::toPlainText() const
    {
        QStringList lines;
        if (!title.isEmpty()) lines.append(title);
        for (const auto& node : nodes) appendText(node, lines, 0, false);
        return lines.join(QLatin1Char('\n'));
    }

    FilePropertyView::FilePropertyView(QWidget* parent) : QWidget(parent)
    {
        setMinimumSize(0, 0);
        setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Ignored);
        auto* layout = new QVBoxLayout(this);
        layout->setContentsMargins(0, 0, 0, 0);
        layout->setSpacing(8);
        m_title = new QLabel(this);
        m_title->setTextFormat(Qt::PlainText);
        m_title->setWordWrap(true);
        m_title->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
        m_title->hide();
        layout->addWidget(m_title);
        auto* toolbar = new QHBoxLayout;
        toolbar->setSpacing(6);
        m_search = new QLineEdit(this);
        m_search->setClearButtonEnabled(true);
        m_search->setMinimumWidth(0);
        m_search->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Fixed);
        toolbar->addWidget(m_search, 1);
        m_style = new QComboBox(this);
        m_style->setSizeAdjustPolicy(QComboBox::AdjustToContents);
        m_style->addItem(QString());
        m_style->addItem(QString());
        toolbar->addWidget(m_style);
        m_copy = new QToolButton(this);
        toolbar->addWidget(m_copy);
        layout->addLayout(toolbar);
        m_tree = new QTreeWidget(this);
        m_tree->setColumnCount(2);
        m_tree->setHeaderHidden(true);
        m_tree->setFrameShape(QFrame::NoFrame);
        m_tree->setSelectionMode(QAbstractItemView::ExtendedSelection);
        m_tree->setSelectionBehavior(QAbstractItemView::SelectRows);
        m_tree->setEditTriggers(QAbstractItemView::NoEditTriggers);
        m_tree->setWordWrap(true);
        m_tree->setUniformRowHeights(false);
        m_tree->setTextElideMode(Qt::ElideNone);
        m_tree->setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);
        m_tree->setHorizontalScrollMode(QAbstractItemView::ScrollPerPixel);
        m_tree->setContextMenuPolicy(Qt::CustomContextMenu);
        m_tree->setItemDelegate(new PropertyDelegate(m_tree));
        m_tree->viewport()->installEventFilter(this);
        m_tree->header()->setMinimumSectionSize(48);
        m_tree->header()->setSectionResizeMode(0, QHeaderView::Interactive);
        m_tree->header()->setSectionResizeMode(1, QHeaderView::Stretch);
        m_tree->header()->setStretchLastSection(true);
        layout->addWidget(m_tree, 1);
        connect(m_search, &QLineEdit::textChanged, this, [this] { applySearch(); });
        connect(m_style, &QComboBox::currentIndexChanged, this, [this](const int index)
        {
            setPresentation(index == 1 ? Presentation::Tree : Presentation::Sections);
        });
        connect(m_copy, &QToolButton::clicked, this, [this] { copyText(plainText()); });
        connect(m_tree, &QTreeWidget::customContextMenuRequested,
            this, [this](const QPoint& position) { showCopyMenu(position); });
        auto* copyShortcut = new QShortcut(QKeySequence::Copy, m_tree);
        copyShortcut->setContext(Qt::WidgetWithChildrenShortcut);
        connect(copyShortcut, &QShortcut::activated, this, [this]
        {
            const auto selected = selectedText();
            copyText(selected.isEmpty() ? plainText() : selected);
        });
        updateTranslations();
        setPresentation(sessionPresentation());
    }

    void FilePropertyView::setDocument(const PropertyDocument& document)
    {
        m_document = document;
        rebuild();
    }

    void FilePropertyView::rebuild()
    {
        QHash<QString, bool> expanded;
        QSet<QString> selected;
        QString current;
        const int scroll = m_tree->verticalScrollBar()->value();
        walkItems(m_tree->invisibleRootItem(), [&](QTreeWidgetItem* item)
        {
            const auto key = item->data(0, KeyRole).toString();
            expanded.insert(key, item->isExpanded());
            if (item->isSelected()) selected.insert(key);
            if (item == m_tree->currentItem()) current = key;
        });
        QSignalBlocker blocker(m_tree);
        m_tree->setUpdatesEnabled(false);
        m_tree->clear();
        QTreeWidgetItem* newCurrent = nullptr;
        std::function<void(const QVector<PropertyNode>&, QTreeWidgetItem*, const QString&)> append;
        append = [&](const QVector<PropertyNode>& nodes, QTreeWidgetItem* parent, const QString& parentKey)
        {
            QHash<QString, int> occurrences;
            for (const auto& node : nodes)
            {
                const QString sourceKey = QString::number(static_cast<int>(node.kind)) + QLatin1Char(':')
                    + (node.kind == PropertyNode::Kind::Note ? node.value : node.name);
                const int occurrence = occurrences[sourceKey]++;
                const QString key = parentKey + QString::number(sourceKey.size()) + QLatin1Char(':')
                    + sourceKey + QLatin1Char(':') + QString::number(occurrence) + QLatin1Char('/');
                auto* item = new QTreeWidgetItem(parent);
                const QString name = translated(node.name);
                const QString value = node.translateValue ? translated(node.value) : node.value;
                QString row;
                if (node.kind == PropertyNode::Kind::Section)
                {
                    item->setText(0, name);
                    row = QLatin1Char('[') + name + QLatin1Char(']');
                }
                else if (node.kind == PropertyNode::Kind::Note)
                {
                    item->setText(0, translated(node.value));
                    row = translated(node.value);
                }
                else
                {
                    item->setText(0, name);
                    item->setText(1, value);
                    row = name + QStringLiteral(": ") + value;
                }
                for (int column = 0; column < 2; ++column)
                {
                    item->setData(column, KindRole, static_cast<int>(node.kind));
                    item->setData(column, KeyRole, key);
                    item->setData(column, RowRole, row);
                    item->setData(column, ValueRole, node.kind == PropertyNode::Kind::Field ? value : item->text(0));
                    item->setToolTip(column, column == 0 ? item->text(0) : value);
                }
                item->setFirstColumnSpanned(node.kind != PropertyNode::Kind::Field);
                append(node.children, item, key);
                const bool defaultExpanded = !node.children.isEmpty();
                item->setExpanded(expanded.value(key, defaultExpanded));
                if (m_searchActive && !m_expansionBeforeSearch.contains(key))
                    m_expansionBeforeSearch.insert(key, defaultExpanded);
                if (selected.contains(key)) item->setSelected(true);
                if (key == current) newCurrent = item;
            }
        };
        append(m_document.nodes, m_tree->invisibleRootItem(), QString());
        if (newCurrent) m_tree->setCurrentItem(newCurrent, 0, QItemSelectionModel::NoUpdate);
        m_title->setText(translated(m_document.title));
        m_title->setVisible(!m_document.title.isEmpty());
        applySearch();
        updateColumns();
        m_tree->setUpdatesEnabled(true);
        m_tree->doItemsLayout();
        m_tree->verticalScrollBar()->setValue(scroll);
    }

    QString FilePropertyView::plainText() const
    {
        QStringList lines;
        if (!m_document.title.isEmpty()) lines.append(translated(m_document.title));
        for (const auto& node : m_document.nodes) appendText(node, lines, 0, true);
        return lines.join(QLatin1Char('\n'));
    }

    QString FilePropertyView::exportItems(const bool selectedOnly) const
    {
        QStringList lines;
        walkItems(m_tree->invisibleRootItem(), [&](QTreeWidgetItem* item)
        {
            if (!selectedOnly || item->isSelected()) lines.append(item->data(0, RowRole).toString());
        });
        return lines.join(QLatin1Char('\n'));
    }

    QString FilePropertyView::selectedText() const { return exportItems(true); }

    PropertyCopySnapshot FilePropertyView::captureCopy(const QModelIndex& clicked) const
    {
        PropertyCopySnapshot snapshot;
        snapshot.all = plainText();
        if (clicked.isValid() && clicked.model() == m_tree->model())
        {
            snapshot.hasRow = true;
            snapshot.value = clicked.data(ValueRole).toString();
            snapshot.row = clicked.data(RowRole).toString();
        }
        return snapshot;
    }

    QString FilePropertyView::searchText() const { return m_search->text(); }
    void FilePropertyView::setSearchText(const QString& text) { m_search->setText(text); }

    void FilePropertyView::applySearch()
    {
        const QString query = m_search->text().trimmed();
        const bool active = !query.isEmpty();
        if (active && !m_searchActive)
        {
            m_expansionBeforeSearch.clear();
            walkItems(m_tree->invisibleRootItem(), [&](QTreeWidgetItem* item)
            {
                m_expansionBeforeSearch.insert(item->data(0, KeyRole).toString(), item->isExpanded());
            });
        }
        std::function<bool(QTreeWidgetItem*, bool)> filter = [&](QTreeWidgetItem* item, const bool parentMatches)
        {
            const bool matches = !active || parentMatches ||
                item->data(0, RowRole).toString().contains(query, Qt::CaseInsensitive);
            bool childMatches = false;
            for (int index = 0; index < item->childCount(); ++index)
                childMatches = filter(item->child(index), matches) || childMatches;
            const bool visible = matches || childMatches;
            item->setHidden(!visible);
            if (active && childMatches) item->setExpanded(true);
            else if (!active && m_searchActive)
                item->setExpanded(m_expansionBeforeSearch.value(item->data(0, KeyRole).toString(), item->isExpanded()));
            return visible;
        };
        for (int index = 0; index < m_tree->topLevelItemCount(); ++index)
            filter(m_tree->topLevelItem(index), false);
        m_searchActive = active;
        if (!active) m_expansionBeforeSearch.clear();
    }

    void FilePropertyView::setPresentation(const Presentation presentation)
    {
        m_presentation = presentation;
        sessionPresentation() = presentation;
        QSignalBlocker blocker(m_style);
        m_style->setCurrentIndex(presentation == Presentation::Tree ? 1 : 0);
        applyPresentation();
    }

    void FilePropertyView::applyPresentation()
    {
        const bool sections = m_presentation == Presentation::Sections;
        m_tree->setRootIsDecorated(!sections);
        m_tree->setIndentation(sections ? 14 : 20);
        m_tree->setAlternatingRowColors(!sections);
        static_cast<PropertyDelegate*>(m_tree->itemDelegate())->sections = sections;
        updateColumns();
        m_tree->doItemsLayout();
        m_tree->viewport()->update();
    }

    void FilePropertyView::updateColumns()
    {
        const int width = m_tree->viewport()->width();
        const int desired = std::clamp(width / 3, 112, 260);
        m_tree->setColumnWidth(0, std::min(desired, std::max(64, width - 80)));
    }

    void FilePropertyView::updateTranslations()
    {
        m_search->setPlaceholderText(translated(QStringLiteral("搜索属性")));
        m_search->setAccessibleName(translated(QStringLiteral("搜索属性")));
        m_style->setItemText(0, translated(QStringLiteral("分区")));
        m_style->setItemText(1, translated(QStringLiteral("树形")));
        m_style->setAccessibleName(translated(QStringLiteral("显示样式")));
        m_copy->setText(translated(QStringLiteral("复制全部")));
        m_tree->setHeaderLabels({translated(QStringLiteral("属性")), translated(QStringLiteral("值"))});
    }

    void FilePropertyView::changeEvent(QEvent* event)
    {
        QWidget::changeEvent(event);
        if (!m_tree) return;
        if (event->type() == QEvent::LanguageChange)
        {
            updateTranslations();
            rebuild();
        }
        else if (event->type() == QEvent::FontChange || event->type() == QEvent::ApplicationFontChange ||
            event->type() == QEvent::PaletteChange || event->type() == QEvent::ApplicationPaletteChange)
        {
            updateColumns();
            m_tree->doItemsLayout();
            m_tree->viewport()->update();
        }
    }

    void FilePropertyView::resizeEvent(QResizeEvent* event)
    {
        QWidget::resizeEvent(event);
        updateColumns();
        m_tree->doItemsLayout();
    }

    bool FilePropertyView::eventFilter(QObject* watched, QEvent* event)
    {
        // The layout gives the tree its final geometry after the parent's
        // resizeEvent. Refresh from that actual viewport width on the next
        // event turn, once Qt has finished its own resize/layout work.
        if (m_tree && watched == m_tree->viewport() && event->type() == QEvent::Resize && !m_layoutPending)
        {
            m_layoutPending = true;
            QTimer::singleShot(0, this, [this]
            {
                m_layoutPending = false;
                updateColumns();
                m_tree->doItemsLayout();
            });
        }
        return QWidget::eventFilter(watched, event);
    }

    void FilePropertyView::copyText(const QString& text)
    {
        if (!text.isEmpty()) QApplication::clipboard()->setText(text);
    }

    void FilePropertyView::showCopyMenu(const QPoint& position)
    {
        const auto clicked = m_tree->indexAt(position);
        if (clicked.isValid())
        {
            auto* item = m_tree->itemAt(position);
            if (item && !item->isSelected()) m_tree->setCurrentItem(item);
        }
        const auto snapshot = captureCopy(clicked);
        const auto selection = selectedText();
        // A parentless stack menu survives a nested event loop that deletes the
        // owning dialog. Only frozen payloads are accessed after exec().
        QMenu menu;
        menu.setPalette(palette());
        menu.setFont(font());
        connect(this, &QObject::destroyed, &menu, &QMenu::close);
        auto* copyValue = menu.addAction(translated(QStringLiteral("复制值")));
        auto* copyRow = menu.addAction(translated(QStringLiteral("复制整行")));
        auto* copySelected = menu.addAction(translated(QStringLiteral("复制选中项")));
        menu.addSeparator();
        auto* copyAll = menu.addAction(translated(QStringLiteral("复制全部")));
        copyValue->setEnabled(snapshot.hasRow);
        copyRow->setEnabled(snapshot.hasRow);
        copySelected->setEnabled(!selection.isEmpty());
        copyAll->setEnabled(!snapshot.all.isEmpty());
        QPointer<FilePropertyView> guard(this);
        const auto action = menu.exec(m_tree->viewport()->mapToGlobal(position));
        if (!guard) return;
        if (action == copyValue) copyText(snapshot.value);
        else if (action == copyRow) copyText(snapshot.row);
        else if (action == copySelected) copyText(selection);
        else if (action == copyAll) copyText(snapshot.all);
    }
}
