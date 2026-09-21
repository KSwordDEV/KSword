#pragma once

#include "../ArkDriverClient/ArkDriverTypes.h"

#include <QString>
#include <QWidget>

#include <cstdint>
#include <vector>

class QLabel;
class QLineEdit;
class QPoint;
class QTableWidget;
class QTabWidget;
class QPushButton;

// KernelIoctlAuditTab：
// - 按 \\Driver 对象集中投影 DriverObject、DeviceObject 与 MajorFunction；
// - 单独显示 KswordARK 统一 dispatch registry；
// - 全部页面均为只读证据，支持统一文本筛选和行/全表复制。
class KernelIoctlAuditTab final : public QWidget
{
public:
    explicit KernelIoctlAuditTab(QWidget* parent = nullptr);
    ~KernelIoctlAuditTab() override = default;

    // requestInitialRefresh：
    // - 仅在用户首次切入“IOCTL 派遣表”子页时发起 R0 查询；
    // - 禁止构造期间的后台预取触发“未启用 R0”提示；
    // - 重复调用保持幂等，不影响工具栏的手动刷新。
    void requestInitialRefresh();

private:
    struct DriverRow
    {
        QString driverName;
        std::uint64_t driverObjectAddress = 0;
        std::uint64_t driverStart = 0;
        std::uint32_t driverSize = 0;
        std::uint32_t driverFlags = 0;
        std::uint32_t majorFunctionCount = 0;
        std::uint32_t returnedDeviceCount = 0;
        std::uint32_t totalDeviceCount = 0;
        std::uint32_t queryStatus = 0;
        std::int32_t lastStatus = 0;
        QString status;
    };

    struct DeviceRow
    {
        QString driverName;
        QString deviceName;
        std::uint32_t relationDepth = 0;
        std::uint32_t deviceType = 0;
        std::uint32_t flags = 0;
        std::uint32_t characteristics = 0;
        std::uint32_t stackSize = 0;
        std::int32_t nameStatus = 0;
        std::uint64_t rootDeviceObjectAddress = 0;
        std::uint64_t deviceObjectAddress = 0;
        std::uint64_t nextDeviceObjectAddress = 0;
        std::uint64_t attachedDeviceObjectAddress = 0;
        std::uint64_t ownerDriverObjectAddress = 0;
    };

    struct DispatchRow
    {
        QString driverName;
        std::uint64_t driverObjectAddress = 0;
        std::uint32_t majorFunction = 0;
        std::uint64_t dispatchAddress = 0;
        std::uint64_t moduleBase = 0;
        QString moduleName;
        std::uint32_t flags = 0;
        bool isStartIo = false;            // true 表示该行是 DriverObject->DriverStartIo，而非 MajorFunction。
        std::uint32_t startIoState = 0;    // KSWORD_ARK_DRIVER_START_IO_STATE_*，仅 isStartIo 时有效。
    };

    struct Snapshot
    {
        std::vector<DriverRow> driverRows;
        std::vector<DeviceRow> deviceRows;
        std::vector<DispatchRow> dispatchRows;
        std::vector<ksword::ark::IoctlRegistryEntry> registryRows;
        QString errorText;
        std::uint32_t queryFailureCount = 0;
        std::uint32_t partialDriverCount = 0;
        std::uint32_t registryTotal = 0;
        std::uint32_t registryDuplicate = 0;
        bool registryOk = false;
    };

    void initializeUi();
    void refreshAsync();
    void applySnapshot(Snapshot snapshot);
    void populateTables();
    void applyFilter();
    void showCopyMenu(QTableWidget* table, const QPoint& position);
    static QString hex64(std::uint64_t value);
    static QString hex32(std::uint32_t value);
    static QString majorFunctionName(std::uint32_t value);
    static QString tableRowText(QTableWidget* table, int row, bool includeHeader);

    QTabWidget* m_innerTabs = nullptr;
    QWidget* m_driverPage = nullptr;
    QWidget* m_devicePage = nullptr;
    QWidget* m_dispatchPage = nullptr;
    QWidget* m_registryPage = nullptr;
    QTableWidget* m_driverTable = nullptr;
    QTableWidget* m_deviceTable = nullptr;
    QTableWidget* m_dispatchTable = nullptr;
    QTableWidget* m_registryTable = nullptr;
    QPushButton* m_refreshButton = nullptr;
    QLineEdit* m_filterEdit = nullptr;
    QPushButton* m_clearFilterButton = nullptr;
    QLabel* m_statusLabel = nullptr;
    std::vector<DriverRow> m_driverRows;
    std::vector<DeviceRow> m_deviceRows;
    std::vector<DispatchRow> m_dispatchRows;
    std::vector<ksword::ark::IoctlRegistryEntry> m_registryRows;
    std::uint32_t m_queryFailureCount = 0;
    std::uint32_t m_partialDriverCount = 0;
    std::uint32_t m_registryTotal = 0;
    std::uint32_t m_registryDuplicate = 0;
    QString m_errorText;
    bool m_registryOk = false;
    bool m_refreshRunning = false;
    bool m_initialRefreshRequested = false;
};
