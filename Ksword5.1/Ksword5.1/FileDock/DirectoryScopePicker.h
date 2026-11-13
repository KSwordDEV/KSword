#pragma once

#include <QWidget>
#include <functional>

class QFileSystemModel;
class QLabel;
class QTreeView;

// Browse and select a scan root; selection never starts a space scan.
// The standard filesystem model fetches only branches opened by the user.
class DirectoryScopePicker final : public QWidget
{
public:
    explicit DirectoryScopePicker(QWidget* parent = nullptr);
    QString selectedPath() const { return m_selectedPath; }
    std::function<void(const QString&)> selectionChanged;
    QSize sizeHint() const override;
protected:
    void changeEvent(QEvent* event) override;
    bool eventFilter(QObject* watched, QEvent* event) override;
private:
    void updateSummary();
    void updateTranslations();
    QFileSystemModel* m_model = nullptr;
    QTreeView* m_tree = nullptr;
    QLabel* m_summary = nullptr;
    QString m_selectedPath;
};
