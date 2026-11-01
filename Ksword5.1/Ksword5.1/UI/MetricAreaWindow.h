#pragma once
#include "MetricAreaCanvas.h"
#include <QDialog>
#include <QStringList>
class QLabel;
class QPushButton;
class QTableView;
class QTabBar;
class QComboBox;
class QResizeEvent;
namespace ks::ui {
class MetricAreaWindow final : public QDialog {
public:
    explicit MetricAreaWindow(QWidget* parent = nullptr);
    void setPresentation(QString metric, QString state, std::vector<MetricAreaNode> nodes);
    void updateState(QString state);
    // Caller-owned presentation labels; an empty identity label hides that column.
    void setSubject(QString allLabel, QString nameLabel, QString identityLabel, QString interactionHint);
    // Programmatic updates are silent. User selection invokes modeChanged once.
    void setModes(QStringList labels, int selected);
    int currentMode() const;
    MetricAreaCanvas* canvas() const { return m_canvas; }
    std::function<void(QString, QPoint)> itemContextRequested;
    std::function<void(QString)> itemActivated;
    std::function<void(int)> modeChanged;
    std::function<void()> appearanceChanged;
protected:
    void changeEvent(QEvent*) override;
    void resizeEvent(QResizeEvent*) override;
private:
    void retranslate();
    void rebuildExcluded();
    void updateModesLayout();
    MetricAreaCanvas* m_canvas = nullptr;
    QLabel *m_status = nullptr, *m_scope = nullptr, *m_excludedLabel = nullptr;
    QPushButton *m_back = nullptr, *m_reset = nullptr;
    class ExcludedModel;
    QTableView* m_excluded = nullptr;
    ExcludedModel* m_excludedModel = nullptr;
    QTabBar* m_modes = nullptr;
    QComboBox* m_modeCombo = nullptr;
    QStringList m_modeLabels;
    QString m_metric, m_state;
    QString m_allLabel, m_nameLabel, m_identityLabel, m_interactionHint;
    bool m_customSubject = false;
};
}
