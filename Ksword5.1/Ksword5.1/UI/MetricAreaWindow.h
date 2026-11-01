#pragma once
#include "MetricAreaCanvas.h"
#include <QDialog>
class QLabel;
class QPushButton;
class QTableWidget;
namespace ks::ui {
class MetricAreaWindow final : public QDialog {
public:
    explicit MetricAreaWindow(QWidget* parent = nullptr);
    void setPresentation(QString metric, QString state, std::vector<MetricAreaNode> nodes);
    void updateState(QString state);
    MetricAreaCanvas* canvas() const { return m_canvas; }
    std::function<void(QString, QPoint)> processContextRequested;
    std::function<void(QString)> processActivated;
    std::function<void()> appearanceChanged;
protected:
    void changeEvent(QEvent*) override;
private:
    void retranslate();
    void rebuildExcluded();
    MetricAreaCanvas* m_canvas = nullptr;
    QLabel *m_status = nullptr, *m_scope = nullptr, *m_excludedLabel = nullptr;
    QPushButton *m_back = nullptr, *m_reset = nullptr;
    QTableWidget* m_excluded = nullptr;
    QString m_metric, m_state;
};
}
