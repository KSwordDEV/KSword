#pragma once

// ============================================================
// HardwareDeviceManagerPage.h
// 作用：
// 1) 提供 System Informer 风格的 PnP 设备树页面；
// 2) 默认只展示当前存在设备，可切换为全部设备并高亮异常设备；
// 3) 通过 SetupAPI/CfgMgr 读取设备属性，不依赖 PowerShell。
// ============================================================

#include "../Framework.h"

#include <QWidget>

#include <atomic> // std::atomic_bool：后台刷新互斥。
#include <vector> // std::vector：保存设备快照并支持树重建。

class QCheckBox;
class QLabel;
class QLineEdit;
class QMenu;
class QPoint;
class QPushButton;
class QSplitter;
class QTreeWidget;
class QTreeWidgetItem;
class QVBoxLayout;
#include "../UI/StructuredFieldView.h"

// HardwareDeviceManagerPage 说明：
// - 输入：Qt 父控件；
// - 处理：异步枚举 PnP 设备并按父子 InstanceId 构建树；
// - 返回行为：页面类无业务返回值，结果直接渲染到树和详情区。
class HardwareDeviceManagerPage final : public QWidget
{
    Q_OBJECT

public:
    // 构造函数：
    // - parent：Qt 父控件；
    // - 处理：初始化 UI 后启动首轮当前设备枚举。
    explicit HardwareDeviceManagerPage(QWidget* parent = nullptr);

    // 析构函数：
    // - 处理：后台线程使用 QPointer 回投，页面销毁后自动放弃 UI 更新；
    // - 返回：无。
    ~HardwareDeviceManagerPage() override = default;

public:
    // DeviceEntry：
    // - 作用：保存一条 PnP 设备节点及其展示字段；
    // - 处理逻辑：后台线程填充，UI 线程按 instanceId/parentInstanceId 建树；
    // - 返回行为：纯数据结构，无函数返回。
    struct DeviceEntry
    {
        QString nameText;             // nameText：FriendlyName 或 DeviceDesc。
        QString manufacturerText;     // manufacturerText：设备厂商。
        QString serviceText;          // serviceText：关联服务名。
        QString classText;            // classText：设备类名。
        QString enumeratorText;       // enumeratorText：枚举器，例如 PCI/USB/ROOT。
        QString installedText;        // installedText：安装时间。
        QString instanceIdText;       // instanceIdText：PnP Instance ID。
        QString parentInstanceIdText; // parentInstanceIdText：父设备 Instance ID。
        QString classGuidText;        // classGuidText：设备类 GUID。
        QString driverText;           // driverText：驱动注册表键或 INF 相关字段。
        QString driverInfPathText;    // driverInfPathText：设备当前使用的 INF 名称或路径。
        QString driverProviderText;   // driverProviderText：驱动提供商。
        QString driverVersionText;    // driverVersionText：驱动版本。
        QString driverDateText;       // driverDateText：驱动日期。
        QString driverRegistryPathText; // driverRegistryPathText：HKLM\SYSTEM\CCS\Control\Class 下的驱动键路径。
        QString serviceImagePathText; // serviceImagePathText：服务 ImagePath，通常指向 .sys 驱动文件。
        QString locationText;         // locationText：位置描述。
        QString hardwareIdsText;      // hardwareIdsText：硬件 ID 列表。
        QString compatibleIdsText;    // compatibleIdsText：兼容 ID 列表。
        QString problemText;          // problemText：异常码摘要。
        QString statusText;           // statusText：DevNode 状态摘要。
        unsigned long problemCode = 0; // problemCode：CM_PROB_*，0 表示无异常。
        bool hasProblem = false;      // hasProblem：是否需要高亮。
        bool isPresent = true;        // isPresent：是否当前存在。
    };

private:
    // initializeUi 作用：
    // - 创建顶部工具栏、设备树和详情面板；
    // - 无输入参数；
    // - 无返回值。
    void initializeUi();

    // initializeConnections 作用：
    // - 连接刷新、显示全部、搜索、树选择等交互；
    // - 无输入参数；
    // - 无返回值。
    void initializeConnections();

    // refreshDevicesAsync 作用：
    // - 在后台线程枚举设备；
    // - forceRefresh 表示用户主动刷新；
    // - 无返回值，结果通过 queued connection 回到 UI。
    void refreshDevicesAsync(bool forceRefresh);

    // applyDeviceSnapshot 作用：
    // - 在 GUI 线程原子替换设备缓存并重建树；
    // - 设备树右键菜单打开时延迟完整快照，避免旧 item 持有失效缓存指针。
    void applyDeviceSnapshot(
        std::vector<DeviceEntry> deviceList,
        bool includeAllDevices);

    // rebuildDeviceTree 作用：
    // - 输入：设备快照列表；
    // - 处理：按 Parent InstanceId 构建树，应用搜索过滤和异常高亮；
    // - 无返回值。
    void rebuildDeviceTree(const std::vector<DeviceEntry>& deviceList);

    // applyFilterToTree 作用：
    // - 根据搜索框内容隐藏不匹配节点；
    // - 父节点若存在匹配子节点则保持可见；
    // - 返回：当前节点或后代是否匹配。
    bool applyFilterToTree(QTreeWidgetItem* itemPointer, const QString& filterText);

    // updateDetailForItem 作用：
    // - 输入：当前选中树节点；
    // - 处理：把节点关联 DeviceEntry 展示到详情区；
    // - 无返回值。
    void updateDetailForItem(QTreeWidgetItem* itemPointer);

    // showDeviceContextMenu 作用：
    // - 输入：设备树局部坐标；
    // - 处理：按当前选中设备构造属性、驱动详情、卸载、删除驱动包等右键菜单；
    // - 返回值：无。
    void showDeviceContextMenu(const QPoint& localPosition);

    // showSelectedDeviceProperties 作用：
    // - 输入：当前树选中的设备；
    // - 处理：打开只读属性对话框，展示 SetupAPI/CfgMgr 已枚举字段；
    // - 返回值：无。
    void showSelectedDeviceProperties();

    // showSelectedDeviceDriverDetails 作用：
    // - 输入：当前树选中的设备；
    // - 处理：打开只读驱动详情对话框，展示 INF、Provider、Version、服务 ImagePath 等字段；
    // - 返回值：无。
    void showSelectedDeviceDriverDetails();

    // copySelectedDeviceInstanceId 作用：
    // - 输入：当前树选中的设备；
    // - 处理：复制 Instance ID 到剪贴板；
    // - 返回值：无。
    void copySelectedDeviceInstanceId();

    // uninstallSelectedDevice 作用：
    // - 输入：当前树选中的设备；
    // - 处理：二次确认后通过 SetupAPI DIF_REMOVE 卸载设备节点；
    // - 返回值：无。
    void uninstallSelectedDevice();

    // deleteSelectedDeviceDriverPackage 作用：
    // - 输入：当前树选中的设备；
    // - 处理：二次确认后通过 SetupUninstallOEMInf 删除 OEM INF 驱动包；
    // - 返回值：无。
    void deleteSelectedDeviceDriverPackage();

    // selectedDeviceEntry 作用：
    // - 输入：当前树选中项；
    // - 处理：从 Qt::UserRole 取回 DeviceEntry 指针；
    // - 返回：成功时返回当前设备指针，否则返回 nullptr。
    const DeviceEntry* selectedDeviceEntry() const;

    // enumerateDevicesSnapshot 作用：
    // - 输入：includeAllDevices 为 true 时枚举历史/非当前设备；
    // - 处理：调用 SetupAPI/CfgMgr 读取设备属性；
    // - 返回：可直接渲染的设备快照。
    static std::vector<DeviceEntry> enumerateDevicesSnapshot(bool includeAllDevices);

private:
    QVBoxLayout* m_rootLayout = nullptr;      // m_rootLayout：页面根布局。
    QLabel* m_statusLabel = nullptr;          // m_statusLabel：刷新状态文本。
    QPushButton* m_refreshButton = nullptr;   // m_refreshButton：刷新按钮。
    QCheckBox* m_showAllDevicesCheck = nullptr; // m_showAllDevicesCheck：是否展示全部设备。
    QCheckBox* m_showProblemOnlyCheck = nullptr; // m_showProblemOnlyCheck：是否只显示异常设备。
    QLineEdit* m_searchEdit = nullptr;        // m_searchEdit：树过滤输入框。
    QSplitter* m_splitter = nullptr;          // m_splitter：设备树/详情分割器。
    QTreeWidget* m_deviceTree = nullptr;      // m_deviceTree：System Informer 风格设备树。
    ks::ui::StructuredFieldView* m_detailEditor = nullptr; // m_detailEditor：选中设备详情。
    std::vector<DeviceEntry> m_deviceList;    // m_deviceList：最近一次完整快照。
    std::atomic_bool m_refreshing{ false };   // m_refreshing：刷新互斥标记。
};
