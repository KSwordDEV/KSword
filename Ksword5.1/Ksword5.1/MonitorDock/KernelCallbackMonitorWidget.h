#pragma once

// ============================================================
// KernelCallbackMonitorWidget.h
// 作用：
// 1) 在 MonitorDock 中展示六类 R0 内核回调遥测；
// 2) 使用独立游标后台读取，不修改回调规则或 AskUser 状态；
// 3) 提供有界缓存、实时过滤、暂停、详情和导出。
// ============================================================

#include "../ArkDriverClient/ArkDriverClient.h"

#include <QWidget>

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <mutex>
#include <thread>
#include <vector>

class QCheckBox;
class QComboBox;
class QLabel;
class QLineEdit;
class QPlainTextEdit;
class QPushButton;
class QSortFilterProxyModel;
class QSpinBox;
class QTimer;
class QVBoxLayout;

namespace ks::ui
{
    class TableActionTableView;
}

class KernelCallbackEventModel;
class KernelCallbackFilterModel;

class KernelCallbackMonitorWidget final : public QWidget
{
public:
    explicit KernelCallbackMonitorWidget(QWidget* parent = nullptr);
    ~KernelCallbackMonitorWidget() override;

private:
    void initializeUi();
    void initializeConnections();
    void startCapture();
    void stopCapture(bool destroying = false);
    void setPaused(bool paused);
    void clearLocalEvents();
    void workerMain();
    void flushPendingEvents();
    void applyFilters();
    void updateActionState();
    void updateStatusLabel();
    void updateDetailPanel();
    void exportVisibleRows();
    unsigned long selectedCategoryMask() const;
    void recordWorkerFailure(const std::string& message, bool unsupported);

    QVBoxLayout* m_rootLayout = nullptr;
    QCheckBox* m_processCheck = nullptr;
    QCheckBox* m_threadCheck = nullptr;
    QCheckBox* m_imageCheck = nullptr;
    QCheckBox* m_registryCheck = nullptr;
    QCheckBox* m_objectCheck = nullptr;
    QCheckBox* m_fileCheck = nullptr;
    QSpinBox* m_maxRowsSpin = nullptr;
    QPushButton* m_startButton = nullptr;
    QPushButton* m_stopButton = nullptr;
    QPushButton* m_pauseButton = nullptr;
    QPushButton* m_clearButton = nullptr;
    QPushButton* m_exportButton = nullptr;
    QComboBox* m_categoryFilterCombo = nullptr;
    QLineEdit* m_operationFilterEdit = nullptr;
    QLineEdit* m_pidFilterEdit = nullptr;
    QLineEdit* m_processFilterEdit = nullptr;
    QLineEdit* m_pathFilterEdit = nullptr;
    QLineEdit* m_resultFilterEdit = nullptr;
    QCheckBox* m_regexCheck = nullptr;
    QCheckBox* m_keepBottomCheck = nullptr;
    QLabel* m_filterStatusLabel = nullptr;
    QLabel* m_statusLabel = nullptr;
    ks::ui::TableActionTableView* m_eventTable = nullptr;
    QPlainTextEdit* m_detailEdit = nullptr;
    KernelCallbackEventModel* m_eventModel = nullptr;
    KernelCallbackFilterModel* m_filterModel = nullptr;
    QTimer* m_uiTimer = nullptr;

    std::atomic_bool m_workerStop{ false };
    std::atomic_bool m_captureRunning{ false };
    std::atomic_bool m_driverCaptureActive{ false };
    std::atomic_bool m_paused{ false };
    std::atomic_bool m_cursorResetRequested{ false };
    std::atomic_uint64_t m_cursorResetValue{ 0 };
    std::atomic_uint64_t m_readerGeneration{ 0 };
    std::atomic_uint64_t m_latestSequence{ 0 };
    std::atomic_uint64_t m_r0DroppedCount{ 0 };
    std::atomic_uint64_t m_cursorLostCount{ 0 };
    std::atomic_uint64_t m_r3DroppedCount{ 0 };
    std::atomic_uint32_t m_runtimeFlags{ 0 };
    std::atomic_uint32_t m_activeCategoryMask{ 0 };
    std::atomic_uint32_t m_ringCapacity{ 0 };
    std::atomic_int m_pendingLimit{ 20000 };
    std::thread m_worker;
    std::mutex m_pendingMutex;
    std::condition_variable m_workerWake;
    std::deque<ksword::ark::CallbackMonitorEventRow> m_pendingEvents;
    std::string m_workerError;
    bool m_workerUnsupported = false;
    QString m_lastDisplayedError;
};
