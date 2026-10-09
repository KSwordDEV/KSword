#pragma once

// HvmViewDialog：EPT 分离视图面板（隐蔽 Hook 与内存隐藏）。
//
// 一个视图让同一个物理页有两份后备：
// - 隐藏（CLOAK）：执行走真实页，读写走影子页 —— 代码照常跑，内存扫描看到的是影子；
// - Hook：读写走真实页，执行走影子页 —— 字节比对看不见的断点。
//
// 两者都靠翻转共享 EPT 叶项实现，因此只在单处理器拓扑上可安装，
// 且常驻期间不能改动视图表。这些限制由驱动强制，面板只如实呈现失败原因。

#include <QDialog>

class QComboBox;
class QLabel;
class QLineEdit;
class QPushButton;
class QTableWidget;

namespace ks::ui
{
    class SnapshotWorkbenchWidget;
}

class HvmViewDialog final : public QDialog
{
    Q_OBJECT

public:
    explicit HvmViewDialog(QWidget* parent = nullptr);

private:
    // buildUi：构造控件树与信号连接。
    void buildUi();
    // refreshViews：后台查询已安装视图并刷新表格。
    void refreshViews(bool preserveStatus = false);
    // startAdd/startRemove/startClear：发起一次后台视图操作。
    void startAdd();
    void startRemove();
    void startClear();
    void startReadShadow();
    void invalidateShadowSnapshot();
    void updateShadowPreview();
    bool parseTargetRequest(unsigned long long* addressOut, bool* virtualOut,
        unsigned long long* cr3Out, unsigned long* processIdOut);
    // setBusy：忙碌期间锁定表单与动作，保持操作参数一致。
    void setBusy(bool busy);
    // updateEnabledState：按写权限与忙碌状态刷新控件可用性。
    void updateEnabledState();
    // updateTargetHint：显示目标所在页与原始页内偏移。
    void updateTargetHint();

    QComboBox* m_kindBox = nullptr;
    QComboBox* m_addressKindBox = nullptr;
    QComboBox* m_seedBox = nullptr;
    QLineEdit* m_addressEdit = nullptr;
    QLineEdit* m_processIdEdit = nullptr;
    QLineEdit* m_cr3Edit = nullptr;
    ks::ui::SnapshotWorkbenchWidget* m_shadowEditor = nullptr;
    QPushButton* m_readShadowButton = nullptr;
    QPushButton* m_discardShadowButton = nullptr;
    QTableWidget* m_viewTable = nullptr;
    QPushButton* m_addButton = nullptr;
    QPushButton* m_removeButton = nullptr;
    QPushButton* m_clearButton = nullptr;
    QPushButton* m_refreshButton = nullptr;
    QLabel* m_statusLabel = nullptr;
    QLabel* m_targetHintLabel = nullptr;
    bool m_busy = false;
    bool m_shadowSnapshotValid = false;
    unsigned long long m_shadowPhysicalAddress = 0;
    unsigned long long m_shadowReadSequence = 0;
};
