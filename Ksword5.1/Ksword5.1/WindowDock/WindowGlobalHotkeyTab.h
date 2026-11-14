#pragma once

#include "../UI/ImmutableValueTable.h"
#include "../ProcessDock/ProcessHotkeyEnumerator.h"
#include <QStringList>
#include <QVector>
#include <QWidget>

#include <cstdint>
#include <memory>
#include <vector>

class QLabel;
class QLineEdit;
class QPoint;
class QPushButton;
class QShowEvent;
class QTableWidget;
class QTimer;
namespace ks::ui { class AsyncOperation; }

// WindowGlobalHotkeyTab：只读汇总全部进程可由 R3 读取的热键。
class WindowGlobalHotkeyTab final : public QWidget
{
public:
    explicit WindowGlobalHotkeyTab(QWidget* parent = nullptr);
    ~WindowGlobalHotkeyTab() override;
    void setAutomaticFirstScan(bool enabled) { m_automaticFirstScan = enabled; }

protected:
    void showEvent(QShowEvent* event) override;

private:
    struct RowValue
    {
        ks::process::UserModeHotkeyRecord record;
        QStringList cells;
        QString identityKey;
        QString rowToken;
    };
    struct PendingRefreshState;

    void initializeUi();
    void refreshAsync();
    void flushPendingSnapshot();
    void appendSnapshotRows(
        std::uint64_t ticket,
        QVector<RowValue> rows,
        std::uint32_t completedProcessCount,
        std::uint32_t totalProcessCount,
        const QString& processName,
        std::uint32_t diagnosticProcessCount);
    void finishRefresh(std::uint64_t ticket, qint64 elapsedMs);
    struct RowChunk;
    void rebuildTable();
    void updateClearActionState();
    void clearSelectedHotkeys();
    void showCopyMenu(const QPoint& position);
    static QString rowClipboardText(ks::ui::ImmutableValueTable* table, int row, bool includeHeader);

    QLineEdit* m_filterEdit = nullptr;
    QPushButton* m_refreshButton = nullptr;
    QPushButton* m_cancelButton = nullptr;
    QPushButton* m_clearButton = nullptr;
    QLabel* m_statusLabel = nullptr;
    ks::ui::ImmutableValueTable* m_table = nullptr;
    QTimer* m_flushTimer = nullptr;
    ks::ui::AsyncOperation* m_clearOperation = nullptr;
    std::shared_ptr<const RowChunk> m_rows;
    qsizetype m_rowCount = 0;
    int m_sortColumnBeforeRefresh = -1;
    Qt::SortOrder m_sortOrderBeforeRefresh = Qt::AscendingOrder;
    std::shared_ptr<PendingRefreshState> m_refreshState;
    bool m_refreshing = false;
    bool m_clearBusy = false;
    bool m_firstRefreshStarted = false;
    bool m_automaticFirstScan = true;
    bool m_sortingEnabledBeforeRefresh = true;
    std::uint64_t m_refreshTicket = 0;
    std::uint64_t m_clearTicket = 0;
    std::uint64_t m_appliedRefreshRevision = 0;
    std::uint32_t m_scannedProcessCount = 0;
    std::uint32_t m_totalProcessCount = 0;
    std::uint32_t m_diagnosticProcessCount = 0;
    QString m_lastClearSummary;
    QString m_lastClearDetails;
    int m_progressTaskId = 0;
};
