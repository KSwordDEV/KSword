#pragma once

#include <QHash>
#include <QModelIndex>
#include <QString>
#include <QVector>
#include <QWidget>

class QComboBox;
class QLabel;
class QLineEdit;
class QToolButton;
class QTreeWidget;
class QTreeWidgetItem;

namespace ks::ui
{
    // Values come from the actual metadata/PE/driver result. They are never
    // reconstructed by parsing a generated report or interpreted as HTML.
    struct FieldNode
    {
        enum class Kind { Section, Field, Note };
        Kind kind = Kind::Field;
        QString name;
        QString value;
        bool translateValue = false;
        QVector<FieldNode> children;
        bool initiallyExpanded = true;
        bool translateName = true;
    };

    struct FieldDocument
    {
        QString title;
        QVector<FieldNode> nodes;

        // Fields and notes append to the most recently started section, or to
        // the document root before the first section. Nested data can be built
        // directly through FieldNode::children without retaining UI pointers.
        FieldDocument& section(const QString& title);
        FieldDocument& field(const QString& name, const QString& value,
            bool translateValue = false);
        FieldDocument& note(const QString& body);
        QString toPlainText(bool localize = false) const;
        bool isEmpty() const { return title.isEmpty() && nodes.isEmpty(); }
    };

    // Copy payloads can be inspected without touching the system clipboard.
    struct FieldCopySnapshot
    {
        QString value;
        QString row;
        QString all;
        bool hasRow = false;
    };

    class StructuredFieldView final : public QWidget
    {
        Q_OBJECT
    public:
        enum class Presentation { Sections, Tree };

        explicit StructuredFieldView(QWidget* parent = nullptr);
        void setDocument(const FieldDocument& document);
        const FieldDocument& document() const { return m_document; }
        QString plainText() const;
        QString selectedText() const;
        bool exportText(const QString& filePath, QString* error = nullptr) const;
        FieldCopySnapshot captureCopy(const QModelIndex& clicked) const;
        void setSearchText(const QString& text);
        QString searchText() const;
        void setPresentation(Presentation presentation);
        Presentation presentation() const { return m_presentation; }
        QTreeWidget* tree() const { return m_tree; }

    signals:
        void documentChanged(); // Emitted once per event turn after a complete value snapshot.

    protected:
        bool eventFilter(QObject* watched, QEvent* event) override;
        void changeEvent(QEvent* event) override;
        void resizeEvent(QResizeEvent* event) override;

    private:
        void rebuild();
        void updateTranslations();
        void applyPresentation();
        void applySearch();
        void updateColumns();
        void showCopyMenu(const QPoint& position);
        void copyText(const QString& text);
        QString exportItems(bool selectedOnly) const;

        FieldDocument m_document;
        Presentation m_presentation = Presentation::Sections;
        QLabel* m_title = nullptr;
        QLineEdit* m_search = nullptr;
        QComboBox* m_style = nullptr;
        QToolButton* m_copy = nullptr;
        QToolButton* m_export = nullptr;
        QTreeWidget* m_tree = nullptr;
        QHash<QString, bool> m_expansionBeforeSearch;
        bool m_searchActive = false;
        bool m_layoutPending = false;
        bool m_documentNotificationPending = false;
    };
}
