#pragma once
#include "WinAPIParameterRules.h"
#include "WinAPISessionBackend.h"
#include <QWidget>
#include <functional>

class QTabBar;
class QLabel;
class QSpinBox;
class QToolButton;
class QPushButton;
namespace ks::ui { class FlowLayout; }
class QScrollArea;

class WinAPIParameterEditor final : public QWidget
{
public:
    explicit WinAPIParameterEditor(QWidget* parent = nullptr);
    void setRecord(WinAPIEventRef record);
    ks::monitor::RawDecodeResult decoded() const;
    std::function<void()> changed;
protected:
    bool eventFilter(QObject* watched, QEvent* event) override;
private:
    void resizeAllocationBar();
    void persist(ks::monitor::RawParameterRule next);
    void rebuild();
    void reorderTypeButtons(int slotWidth);
    WinAPIEventRef m_record;
    ks::monitor::WinAPIParameterRules m_rules;
    ks::monitor::RawParameterRule m_rule;
    ks::monitor::RawParameterRule m_dragOriginal;
    QString m_key;
    bool m_validConfig = false;
    bool m_dragDirty = false;
    QTabBar* m_allocations = nullptr;
    QLabel* m_remainder = nullptr;
    QWidget* m_allocationContent = nullptr;
    QScrollArea* m_allocationScroll = nullptr;
    ks::ui::FlowLayout* m_typeActions = nullptr;
    int m_orderedSlotWidth = 0;
    int m_orderedByteCount = 0;
    QLabel* m_status = nullptr;
    QSpinBox* m_byteCount = nullptr;
    QToolButton* m_parameterMode = nullptr;
    QToolButton* m_byteMode = nullptr;
    QList<QPushButton*> m_addButtons;
};
