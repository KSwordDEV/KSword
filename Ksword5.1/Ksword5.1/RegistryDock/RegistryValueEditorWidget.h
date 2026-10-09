#pragma once

#include <QByteArray>
#include <QString>
#include <QWidget>

namespace ks::ui
{
    class HexView;
}
class QComboBox;
class QLabel;
class QLineEdit;
class QPlainTextEdit;
class QPushButton;
class QStackedWidget;
class QTabWidget;

struct RegistryValueDraft
{
    QString name;
    quint32 type = 0;
    QByteArray data;
};

// Backend-independent registry draft editor. setValue establishes an immutable
// baseline; the owning Dock validates target identity, writes and reads back.
// value() returns complete bytes, never a list/display preview or truncated data.
class RegistryValueEditorWidget final : public QWidget
{
    Q_OBJECT

public:
    explicit RegistryValueEditorWidget(QWidget* parent = nullptr);
    void setValue(const QString& keyPath, const QString& name, quint32 type,
        const QByteArray& raw, bool createMode = false);
    bool value(RegistryValueDraft* out, QString* errorOut = nullptr) const;
    bool isModified() const;
    void discardChanges();

signals:
    void draftChanged();

protected:
    void changeEvent(QEvent* event) override;

private:
    quint32 currentType() const;
    void loadTypedEditor();
    void loadHexEditor();
    void updateComparison();
    void updateState();
    void editText();
    void editNumber(bool hexadecimal);
    void stageBytes(const QByteArray& bytes);
    void changeType();
    void changeTab(int index);
    void importBytes();
    void exportBytes();
    void resizeBytes();
    void chooseConsoleColor();
    void updateExpandPreview();
    void updateConsoleColor();
    bool isConsoleColor() const;
    void applyControlStyles();

    QLabel* m_path = nullptr;
    QLineEdit* m_name = nullptr;
    QComboBox* m_type = nullptr;
    QLabel* m_metadata = nullptr;
    QLabel* m_state = nullptr;
    QPushButton* m_discard = nullptr;
    QTabWidget* m_tabs = nullptr;
    QStackedWidget* m_typedPages = nullptr;
    QPlainTextEdit* m_text = nullptr;
    QLabel* m_expandedTitle = nullptr;
    QPlainTextEdit* m_expanded = nullptr;
    QPlainTextEdit* m_multi = nullptr;
    QLineEdit* m_hexNumber = nullptr;
    QLineEdit* m_decimalNumber = nullptr;
    QLabel* m_range = nullptr;
    QPushButton* m_consoleColor = nullptr;
    ks::ui::HexView* m_hex = nullptr;
    QLineEdit* m_resizeSize = nullptr;
    ks::ui::HexView* m_before = nullptr;
    ks::ui::HexView* m_after = nullptr;

    QString m_keyPath;
    QString m_originalName;
    quint32 m_originalType = 0;
    QByteArray m_original;
    QByteArray m_working;
    QString m_originalTypedText;
    QString m_dataError;
    QString m_operationError;
    QString m_formatWarning;
    bool m_originalTypedValid = false;
    bool m_createMode = false;
    bool m_syncing = false;
    bool m_typedNeedsRefresh = false;
    bool m_hexNeedsRefresh = false;
    quint64 m_revision = 0;
};
