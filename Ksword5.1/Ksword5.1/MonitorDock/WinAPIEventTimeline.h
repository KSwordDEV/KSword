#pragma once
#include "WinAPISessionBackend.h"
#include "WinAPITimelineDensity.h"
#include "../UI/AsyncOperation.h"
#include <QWidget>
#include <QPointer>
class QCheckBox;
class QTableView;
class QTimer;
class ProcessTraceTimelineWidget;
class WinAPIEventTableModel;
class WinAPIEventFilterModel;

// Session-wide approximate density; never retains event identities or payloads.
class WinAPIEventTimeline final : public QWidget
{
public:
    WinAPIEventTimeline(QWidget* parent, WinAPIEventTableModel* model,
        WinAPIEventFilterModel* proxy, QTableView* table, QCheckBox* keepBottom);
    ~WinAPIEventTimeline() override;
    void appendRecord(const WinAPIEventRef& record);
    void resetTimeline();
protected:
    void showEvent(QShowEvent* event) override;
private:
    void scheduleRefresh();
    void refresh();
    QPointer<WinAPIEventTableModel> m_model;
    ProcessTraceTimelineWidget* m_timeline = nullptr;
    QTimer* m_timer = nullptr;
    QTimer* m_filterTimer = nullptr;
    ks::ui::AsyncOperation* m_project = nullptr;
    ks::monitor::WinAPITimelineDensity m_density;
    std::uint64_t m_epoch = 0, m_revision = 0, m_missingTime = 0;
    bool m_dirty = false;
};
