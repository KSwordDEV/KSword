#include "../UI/StructuredFieldView.h"
#pragma once

// ============================================================
// HardwareOtherDevicesPage.h
// 作用：
// 1) 提供硬件页内“其他设备”侧边 Tab，承载 CPU/内存/GPU 之外的硬件清单；
// 2) 通过后台 PowerShell/CIM 采集主板、BIOS、存储、USB、音频、显示器、HID 等信息；
// 3) 使用只读文本视图展示详细枚举结果，避免阻塞主窗口和现有 HardwareDock。
// ============================================================

#include "../Framework.h"

#include <QWidget>

#include <atomic> // std::atomic_bool：避免重复启动硬件清单刷新线程。

class CodeEditorWidget;
class QLabel;
class QPushButton;
class QVBoxLayout;

// HardwareOtherDevicesPage 说明：
// - 输入：Qt 父对象；
// - 处理逻辑：初始化顶部状态栏和只读文本区，后台执行设备枚举；
// - 返回行为：无业务返回值，采集结果显示在 UI 中。
class HardwareOtherDevicesPage final : public QWidget
{
    Q_OBJECT

public:
    // 构造函数：
    // - parent 为 Qt 父控件；
    // - 初始化 UI 后立即触发一次异步刷新。
    explicit HardwareOtherDevicesPage(QWidget* parent = nullptr);

    // 析构函数：
    // - 当前类不持有阻塞线程句柄；
    // - 后台回投使用 QPointer 防止对象销毁后访问。
    ~HardwareOtherDevicesPage() override = default;

private:
    // initializeUi 作用：
    // - 创建状态标签、刷新按钮、只读文本编辑器；
    // - 处理逻辑只操作 Qt 控件；
    // - 无返回值。
    void initializeUi();

    // initializeConnections 作用：
    // - 连接刷新按钮到异步采集入口；
    // - 无输入参数；
    // - 无返回值。
    void initializeConnections();

    // refreshDeviceInventoryAsync 作用：
    // - 后台执行 PowerShell/CIM 设备枚举；
    // - forceRefresh 表示用户主动刷新时覆盖状态文本；
    // - 无返回值，结果通过 queued connection 回到 UI。
    void refreshDeviceInventoryAsync(bool forceRefresh);

    // buildDeviceInventoryTextSnapshot 作用：
    // - 在工作线程中构建完整硬件设备清单文本；
    // - 不访问任何 QWidget；
    // - 返回设备清单或错误诊断文本。
    static ks::ui::FieldDocument buildDeviceInventoryTextSnapshot();

private:
    QVBoxLayout* m_rootLayout = nullptr;      // m_rootLayout：页内根布局。
    QLabel* m_statusLabel = nullptr;          // m_statusLabel：显示刷新状态与时间。
    QPushButton* m_refreshButton = nullptr;   // m_refreshButton：手动刷新按钮。
    ks::ui::StructuredFieldView* m_inventoryEditor = nullptr; // m_inventoryEditor：只读设备清单文本区。
    std::atomic_bool m_refreshing{ false };   // m_refreshing：异步刷新互斥标志。
};
