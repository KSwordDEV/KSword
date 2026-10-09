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

namespace file_dock_detail
{
    // Values come from the actual metadata/PE/driver result. They are never
    // reconstructed by parsing a generated report or interpreted as HTML.
    struct PropertyNode
    {
        enum class Kind { Section, Field, Note };
        Kind kind = Kind::Field;
        QString name;
        QString value;
        bool translateValue = false;
        QVector<PropertyNode> children;
    };

    struct PropertyDocument
    {
        QString title;
        QVector<PropertyNode> nodes;

        // Fields and notes append to the most recently started section, or to
        // the document root before the first section. Nested data can be built
        // directly through PropertyNode::children without retaining UI pointers.
        PropertyDocument& section(const QString& title);
        PropertyDocument& field(const QString& name, const QString& value,
            bool translateValue = false);
        PropertyDocument& note(const QString& body);
        QString toPlainText() const;
    };

    // Copy payloads can be inspected without touching the system clipboard.
    struct PropertyCopySnapshot
    {
        QString value;
        QString row;
        QString all;
        bool hasRow = false;
    };

    class FilePropertyView final : public QWidget
    {
    public:
        enum class Presentation { Sections, Tree };

        explicit FilePropertyView(QWidget* parent = nullptr);
        void setDocument(const PropertyDocument& document);
        const PropertyDocument& document() const { return m_document; }
        QString plainText() const;
        QString selectedText() const;
        PropertyCopySnapshot captureCopy(const QModelIndex& clicked) const;
        void setSearchText(const QString& text);
        QString searchText() const;
        void setPresentation(Presentation presentation);
        Presentation presentation() const { return m_presentation; }
        QTreeWidget* tree() const { return m_tree; }

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

        PropertyDocument m_document;
        Presentation m_presentation = Presentation::Sections;
        QLabel* m_title = nullptr;
        QLineEdit* m_search = nullptr;
        QComboBox* m_style = nullptr;
        QToolButton* m_copy = nullptr;
        QTreeWidget* m_tree = nullptr;
        QHash<QString, bool> m_expansionBeforeSearch;
        bool m_searchActive = false;
        bool m_layoutPending = false;
    };
}
