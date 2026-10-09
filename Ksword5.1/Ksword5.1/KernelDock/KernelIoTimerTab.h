#pragma once

// ============================================================
// KernelIoTimerTab.h
// 作用说明：
// 1) 枚举对象命名空间中的 DriverObject，并通过 ArkDriverClient 查询其 DeviceObject；
// 2) 展示 WDK 公开 DEVICE_OBJECT.Timer 字段形成的 IoTimer 清单；
// 3) 经双重确认后由 R0 重新核对 DriverObject/DeviceObject/PIO_TIMER，
//    再调用公开 IoStartTimer/IoStopTimer；不解引用私有 IO_TIMER 布局。
// ============================================================

#include <QWidget>

#include <atomic>  // std::atomic_bool：首轮/手动刷新互斥。
#include <cstdint> // std::uintXX_t：固定宽度地址与计数。
#include <vector>  // std::vector：后台快照与 UI 行缓存。

#include "../UI/StructuredFieldView.h"
class QEvent;
class QLabel;
class QLineEdit;
class QPoint;
class QPushButton;
class QTableWidget;

// KernelIoTimerTab：旧版 SKT64 IoTimer 视图的安全等效实现。
class KernelIoTimerTab final : public QWidget
{
public:
    explicit KernelIoTimerTab(QWidget* parent = nullptr);

    // requestInitialRefresh：仅在用户第一次打开子页时触发昂贵的全 DriverObject 查询。
    void requestInitialRefresh();

protected:
    void changeEvent(QEvent* event) override;

private:
    enum class Column
    {
        TimerAddress = 0,
        DeviceObject,
        DriverObject,
        DriverName,
        DeviceName,
        NamespacePath,
        QueryStatus,
        Count
    };

    // IoTimerRow：一个带非空 DEVICE_OBJECT.Timer 的设备对象快照。
    struct IoTimerRow
    {
        std::uint64_t timerAddress = 0;
        std::uint64_t deviceObjectAddress = 0;
        std::uint64_t driverObjectAddress = 0;
        QString driverName;
        QString deviceName;
        QString namespacePath;
        QString imagePath;
        QString queryStatus;
        std::uint32_t queryProtocolVersion = 0;
        std::uint32_t queryFieldFlags = 0;
    };

    // Snapshot：后台全量查询结果和完整性统计。
    struct Snapshot
    {
        std::vector<IoTimerRow> rows;
        QString namespaceError;
        std::uint32_t driverObjectsDiscovered = 0;
        std::uint32_t driverObjectsQueried = 0;
        std::uint32_t queryFailures = 0;
        std::uint32_t partialQueries = 0;
        std::uint32_t duplicateTimersSkipped = 0;
    };

    void initializeUi();
    void applyTranslatedText();
    void refreshAsync();
    void applySnapshot(const Snapshot& snapshot);
    void rebuildTable();
    void updateDetail();
    void updateControlActions();
    void showContextMenu(const QPoint& localPosition);
    void runControlAction(std::uint32_t action);

    const IoTimerRow* selectedRow() const;

    static Snapshot collectSnapshot();
    static QString pointerText(std::uint64_t address);
    static QString normalizedCellText(const QString& text);

    QPushButton* m_refreshButton = nullptr;
    QPushButton* m_startButton = nullptr;
    QPushButton* m_stopButton = nullptr;
    QLineEdit* m_filterEdit = nullptr;
    QLabel* m_statusLabel = nullptr;
    QTableWidget* m_table = nullptr;
    ks::ui::StructuredFieldView* m_detailEditor = nullptr;

    std::vector<IoTimerRow> m_rows;
    Snapshot m_lastSnapshot;
    std::atomic_bool m_refreshRunning{ false };
    bool m_initialRefreshRequested = false;
    std::uint64_t m_refreshTicket = 0;
};
