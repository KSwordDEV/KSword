#pragma once
#include "WinAPIParameterRules.h"
#include "WinAPISignatureCatalog.h"
#include "WinAPICallerSnapshotAdapter.h"
#include "WinAPIStackSnapshotAdapter.h"
#include <optional>
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
    void setSignatureCatalog(std::shared_ptr<const ks::monitor::WinAPISignatureCatalog> catalog);
    const ks::monitor::WinAPISignature* signature() const;
    const ks::winapi_monitor::CallerSnapshot* callerSnapshot() const
    { return m_callerSnapshot ? &*m_callerSnapshot : nullptr; }
    const std::vector<ks::winapi_monitor::StackFrameSnapshot>& stackSnapshot() const { return m_stackSnapshot; }
    std::function<void()> changed;
protected:
    bool eventFilter(QObject* watched, QEvent* event) override;
private:
    void resizeAllocationBar();
    void persist(ks::monitor::RawParameterRule next);
    void rebuild();
    void reorderTypeButtons(int slotWidth);
    WinAPIEventRef m_record;
    WinAPICallerSnapshotAdapter* m_callerAdapter = nullptr;
    WinAPIStackSnapshotAdapter* m_stackAdapter = nullptr;
    std::vector<ks::winapi_monitor::StackFrameSnapshot> m_stackSnapshot;
    std::optional<ks::winapi_monitor::CallerSnapshot> m_callerSnapshot;
    std::shared_ptr<const ks::monitor::WinAPISignatureCatalog> m_signatureCatalog;
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
