#pragma once

#include "../ArkDriverClient/ArkDriverTypes.h"

#include <QString>
#include <QWidget>

#include <cstdint>
#include <vector>

class QLabel;
class QLineEdit;
class QPoint;
class QPushButton;
class QTableWidget;

// KernelDriverStartIoTab：
// - 按 \\Driver 对象逐个查询 DriverObject->DriverStartIo，并解析所属模块与镜像路径；
// - 状态分三态：空值、读取失败、非空；空值是常态，不渲染成 0 地址；
// - 全部为只读证据，支持文本筛选与行/全表复制，不提供任何修改入口。
class KernelDriverStartIoTab final : public QWidget
{
public:
    explicit KernelDriverStartIoTab(QWidget* parent = nullptr);
    ~KernelDriverStartIoTab() override = default;

    // requestInitialRefresh：
    // - 仅在用户首次切入本子页时发起 R0 查询；
    // - 重复调用保持幂等，不影响工具栏的手动刷新。
    void requestInitialRefresh();

private:
    struct StartIoRow
    {
        QString driverName;
        QString imagePath;
        std::uint64_t driverObjectAddress = 0;
        std::uint64_t startIoAddress = 0;
        std::uint64_t moduleBase = 0;
        QString moduleName;
        std::uint32_t flags = 0;
        std::uint32_t state = 0;       // KSWORD_ARK_DRIVER_START_IO_STATE_*。
        std::int32_t lastStatus = 0;
        QString queryError;            // 非空表示 DriverObject 查询本身失败。
    };

    struct Snapshot
    {
        std::vector<StartIoRow> rows;
        QString errorText;
        std::uint32_t presentCount = 0;
        std::uint32_t nullCount = 0;
        std::uint32_t readFailedCount = 0;
        std::uint32_t queryFailureCount = 0;
        std::uint32_t notQueriedCount = 0;
    };

    void initializeUi();
    void refreshAsync();
    void applySnapshot(Snapshot snapshot);
    void populateTable();
    void applyFilter();
    void showCopyMenu(const QPoint& position);
    QString stateText(const StartIoRow& row) const;
    static QString hex64(std::uint64_t value);
    static QString hex32(std::uint32_t value);
    static QString tableRowText(QTableWidget* table, int row, bool includeHeader);

    QTableWidget* m_table = nullptr;
    QPushButton* m_refreshButton = nullptr;
    QLineEdit* m_filterEdit = nullptr;
    QPushButton* m_clearFilterButton = nullptr;
    QLabel* m_statusLabel = nullptr;
    std::vector<StartIoRow> m_rows;
    QString m_errorText;
    std::uint32_t m_presentCount = 0;
    std::uint32_t m_nullCount = 0;
    std::uint32_t m_readFailedCount = 0;
    std::uint32_t m_queryFailureCount = 0;
    std::uint32_t m_notQueriedCount = 0;
    bool m_refreshRunning = false;
    bool m_initialRefreshRequested = false;
};
