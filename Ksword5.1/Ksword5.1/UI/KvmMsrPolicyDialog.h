#pragma once

// KvmMsrPolicyDialog：MSR 策略面板。
//
// P0 装上的 MSR bitmap 让所有 MSR 原生放行 —— 这是常驻能活下来的前提。
// 一条策略就是在位图上开一个洞：被点名的 MSR 重新开始 VM-exit，
// 由分发器决定 guest 拿到什么，而不是让硬件直接给。
//
// 写方向比读方向弱：在 VMX root 里重放任意 WRMSR，值非法时会在 host IDT 上出错
// 且没有续点，所以写策略只能拒绝或吞掉，不提供"记录后放行"。

#include <QDialog>

class QComboBox;
class QLabel;
class QLineEdit;
class QPushButton;
class QTableWidget;

class KvmMsrPolicyDialog final : public QDialog
{
    Q_OBJECT

public:
    explicit KvmMsrPolicyDialog(QWidget* parent = nullptr);

private:
    // buildUi：构造控件树与信号连接。
    void buildUi();
    // refreshPolicies：后台查询已安装策略并刷新表格。
    void refreshPolicies();
    // startAdd/startRemove/startClear：发起一次后台策略操作。
    void startAdd();
    void startRemove();
    void startClear();
    // setBusy：忙碌期间禁用全部动作按钮。
    void setBusy(bool busy);
    // updateEnabledState：按写权限、所选动作与忙碌状态刷新控件可用性。
    void updateEnabledState();

    QLineEdit* m_msrEdit = nullptr;
    QComboBox* m_accessBox = nullptr;
    QComboBox* m_actionBox = nullptr;
    QLineEdit* m_fakeValueEdit = nullptr;
    QTableWidget* m_policyTable = nullptr;
    QPushButton* m_addButton = nullptr;
    QPushButton* m_removeButton = nullptr;
    QPushButton* m_clearButton = nullptr;
    QPushButton* m_refreshButton = nullptr;
    QLabel* m_statusLabel = nullptr;
    bool m_busy = false;
};
