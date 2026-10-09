#include "../UI/StructuredFieldView.h"
#pragma once

// ============================================================
// HardwareHwidDispatchPage.h
// 作用：
// 1) 在硬件 Dock 中集中承载 EASY-HWID-SPOOFER 的 Dispatch 派遣函数方案；
// 2) 只提供“修改驱动程序派遣函数(兼容性强)”图形入口和 KswordARK IOCTL 调用；
// 3) 进入页面先弹蓝屏风险提示，不呈现物理内存修改方案。
// ============================================================

#include "../Framework.h"
#include "../ArkDriverClient/ArkDriverTypes.h"

#include <QWidget>

class CodeEditorWidget;
class QCheckBox;
class QComboBox;
class QGridLayout;
class QLabel;
class QLineEdit;
class QPushButton;
class QShowEvent;
class QTableWidget;
class QVBoxLayout;

// HardwareHwidDispatchPage：
// - 输入：Qt 父控件；
// - 处理：构建 HWID Dispatch 控制台、生成控制请求并通过 ArkDriverClient 下发；
// - 返回行为：页面类无业务返回值，R0 响应显示在表格与日志中。
class HardwareHwidDispatchPage final : public QWidget
{
    Q_OBJECT

public:
    // 构造函数：
    // - parent：Qt 父控件；
    // - 处理：初始化 UI、连接按钮并生成初始计划文本。
    explicit HardwareHwidDispatchPage(QWidget* parent = nullptr);

protected:
    // showEvent：
    // - 输入：Qt 显示事件；
    // - 处理：首次进入页面时弹出蓝屏风险提示并刷新驱动状态；
    // - 返回：无返回值。
    void showEvent(QShowEvent* event) override;

private:
    // initializeUi：
    // - 创建标题、范围说明、Dispatch 目标、参数表单、操作按钮和状态表；
    // - 无输入参数；
    // - 无返回值。
    void initializeUi();

    // initializeConnections：
    // - 连接刷新、干跑、启用、卸载和复制计划按钮；
    // - 无输入参数；
    // - 无返回值。
    void initializeConnections();

    // showBlueScreenWarningOnce：
    // - 首次显示时提示用户该页操作可能导致蓝屏；
    // - 无输入参数；
    // - 无返回值。
    void showBlueScreenWarningOnce();

    // refreshStatus：
    // - 调用 IOCTL_KSWORD_ARK_HWID_DISPATCH_QUERY；
    // - 无输入参数；
    // - 无返回值，结果写入状态表和日志。
    void refreshStatus();

    // sendControlRequest：
    // - 输入：action 为协议动作，dryRun 表示只验证不修改；
    // - 处理：构造请求、必要时二次确认，然后调用 ArkDriverClient；
    // - 无返回值，结果写入状态表和日志。
    void sendControlRequest(unsigned long action, bool dryRun);

    // buildControlRequest：
    // - 输入：action 与 dryRun；
    // - 处理：从 UI 表单复制目标、模式和自定义文本；
    // - 返回：完整共享协议请求结构。
    KSWORD_ARK_HWID_DISPATCH_CONTROL_REQUEST buildControlRequest(unsigned long action, bool dryRun) const;

    // selectedTargetFlags：
    // - 输入：无；
    // - 处理：读取目标复选框；
    // - 返回：KSWORD_ARK_HWID_DISPATCH_TARGET_* 位图。
    unsigned long selectedTargetFlags() const;

    // buildPlanText：
    // - 输入：无；
    // - 处理：把当前 UI 配置转换为可复制的执行计划；
    // - 返回：计划文本。
    ks::ui::FieldDocument buildPlanText() const;

    // updatePlanPreview：
    // - 输入：无；
    // - 处理：刷新只读计划预览；
    // - 无返回值。
    void updatePlanPreview();

    // applyResponseToUi：
    // - 输入：ArkDriverClient 的 HWID Dispatch 结果；
    // - 处理：刷新状态标签、目标表格和日志；
    // - 无返回值。
    void applyResponseToUi(const ksword::ark::HwidDispatchResult& result);

    // appendLogLine：
    // - 输入：日志行；
    // - 处理：追加到页面只读日志；
    // - 无返回值。
    void appendLogLine(const QString& lineText);

private:
    QVBoxLayout* m_rootLayout = nullptr;      // m_rootLayout：页面根布局。
    QLabel* m_statusLabel = nullptr;          // m_statusLabel：顶部状态摘要。
    QCheckBox* m_diskCheck = nullptr;         // m_diskCheck：\\Driver\\Disk 目标。
    QCheckBox* m_partMgrCheck = nullptr;      // m_partMgrCheck：\\Driver\\partmgr 目标。
    QCheckBox* m_mountMgrCheck = nullptr;     // m_mountMgrCheck：\\Driver\\mountmgr 目标。
    QCheckBox* m_nvidiaCheck = nullptr;       // m_nvidiaCheck：\\Driver\\nvlddmkm 目标。
    QCheckBox* m_nsiProxyCheck = nullptr;     // m_nsiProxyCheck：\\Driver\\nsiproxy 目标。
    QCheckBox* m_diskGuidCheck = nullptr;     // m_diskGuidCheck：GPT GUID 随机化标记。
    QCheckBox* m_volumeCleanCheck = nullptr;  // m_volumeCleanCheck：MountMgr 卷 ID 清理标记。
    QCheckBox* m_arpCleanCheck = nullptr;     // m_arpCleanCheck：ARP 表清理标记。
    QComboBox* m_diskModeCombo = nullptr;     // m_diskModeCombo：磁盘序列号模式。
    QComboBox* m_macModeCombo = nullptr;      // m_macModeCombo：MAC 模式。
    QLineEdit* m_diskSerialEdit = nullptr;    // m_diskSerialEdit：自定义磁盘序列号。
    QLineEdit* m_diskProductEdit = nullptr;   // m_diskProductEdit：自定义磁盘产品名。
    QLineEdit* m_diskRevisionEdit = nullptr;  // m_diskRevisionEdit：自定义磁盘固件版本。
    QLineEdit* m_gpuSerialEdit = nullptr;     // m_gpuSerialEdit：自定义 GPU 序列号。
    QLineEdit* m_permanentMacEdit = nullptr;  // m_permanentMacEdit：永久 MAC。
    QLineEdit* m_currentMacEdit = nullptr;    // m_currentMacEdit：当前 MAC。
    QPushButton* m_refreshButton = nullptr;   // m_refreshButton：查询状态按钮。
    QPushButton* m_dryRunButton = nullptr;    // m_dryRunButton：干跑验证按钮。
    QPushButton* m_enableButton = nullptr;    // m_enableButton：启用 Dispatch 按钮。
    QPushButton* m_disableButton = nullptr;   // m_disableButton：卸载 Dispatch 按钮。
    QPushButton* m_copyPlanButton = nullptr;  // m_copyPlanButton：复制计划按钮。
    QTableWidget* m_statusTable = nullptr;    // m_statusTable：目标驱动状态表。
    ks::ui::StructuredFieldView* m_planEditor = nullptr; // m_planEditor：只读计划/日志文本。
    bool m_warningShown = false;              // m_warningShown：首次进入弹窗状态。
};
