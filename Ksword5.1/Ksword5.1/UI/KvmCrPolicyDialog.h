#pragma once

// KvmCrPolicyDialog：控制寄存器策略面板。
//
// 钉住（pin）走的是 VMCS 的 guest/host 掩码：被钉的位归 hypervisor 所有，
// guest 从影子里读它、改它会 VM-exit 并被驳回，但影子仍然回报"改成功了"。
// 这就是把 CR0.WP 或 CR4.SMEP 钉死、让清它的代码以为自己得手的做法。
//
// 跟踪 CR3 是这套协议里最贵的一个开关：Windows 每秒切换地址空间数千次，
// 每次都会变成一次 VM-exit。默认关闭，界面上必须把代价说清楚。
//
// 掩码与开关都在建 VMCS 时消费，所以必须在常驻启动之前配置。

#include <QDialog>

class QCheckBox;
class QLabel;
class QLineEdit;
class QPushButton;

class KvmCrPolicyDialog final : public QDialog
{
    Q_OBJECT

public:
    explicit KvmCrPolicyDialog(QWidget* parent = nullptr);

private:
    // buildUi：构造控件树与信号连接。
    void buildUi();
    // refreshPolicy：后台读取当前配置与计数。
    void refreshPolicy();
    // startApply/startClear：发起一次后台配置操作。
    void startApply();
    void startClear();
    // setBusy：忙碌期间禁用全部动作按钮。
    void setBusy(bool busy);
    // updateEnabledState：按写权限与忙碌状态刷新控件可用性。
    void updateEnabledState();
    // collectMasks：把快捷勾选与手工输入合并成最终掩码。
    bool collectMasks(unsigned long long* cr0Out, unsigned long long* cr4Out);

    QCheckBox* m_pinWpCheck = nullptr;
    QCheckBox* m_pinSmepCheck = nullptr;
    QCheckBox* m_pinSmapCheck = nullptr;
    QCheckBox* m_pinUmipCheck = nullptr;
    QLineEdit* m_cr0MaskEdit = nullptr;
    QLineEdit* m_cr4MaskEdit = nullptr;
    QCheckBox* m_trackCr3Check = nullptr;
    QCheckBox* m_interceptDrCheck = nullptr;
    QCheckBox* m_logCheck = nullptr;
    QPushButton* m_applyButton = nullptr;
    QPushButton* m_clearButton = nullptr;
    QPushButton* m_refreshButton = nullptr;
    QLabel* m_currentLabel = nullptr;
    QLabel* m_statusLabel = nullptr;
    bool m_busy = false;
};
