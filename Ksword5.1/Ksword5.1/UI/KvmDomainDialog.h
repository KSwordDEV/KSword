#pragma once

// KvmDomainDialog：EPT 执行域面板。
//
// 一个域是默认视图的一份分叉，发布在 EPTP list 里。guest 用一条 VMFUNC 就能
// 切过去，而 VMFUNC 不做 CPL 检查——任何 ring 3 线程都能切，不产生 VM exit，
// 驱动也不会被通知。
//
// 因此这个面板只提供「减权限」一个方向：域建出来时与默认视图完全一致，之后
// 只能被拿掉权限。切进域的线程结构性地拿不到它原本没有的访问权，最坏是自己
// 吃一个 EPT violation。
//
// 建域本身不改变任何运行行为。要让 VMFUNC 真的可用，还得用带 ENABLE_VMFUNC
// 的常驻启动，那是标题栏 KVM 菜单里另一个独立开关。

#include <QDialog>

class QCheckBox;
class QLabel;
class QLineEdit;
class QPushButton;
class QTableWidget;

class KvmDomainDialog final : public QDialog
{
    Q_OBJECT

public:
    explicit KvmDomainDialog(QWidget* parent = nullptr);

private:
    // buildUi：构造控件树与信号连接。
    void buildUi();
    // refreshDomains：后台查询 EPTP list 并刷新表格。
    void refreshDomains();
    // startCreate/startRestrict/startReset：发起一次后台域操作。
    void startCreate();
    void startRestrict();
    void startReset();
    // setBusy：忙碌期间禁用全部动作按钮。
    void setBusy(bool busy);
    // updateEnabledState：按写权限与忙碌状态刷新控件可用性。
    void updateEnabledState();

    QLineEdit* m_domainEdit = nullptr;
    QLineEdit* m_addressEdit = nullptr;
    QLineEdit* m_lengthEdit = nullptr;
    QCheckBox* m_denyReadBox = nullptr;
    QCheckBox* m_denyWriteBox = nullptr;
    QCheckBox* m_denyExecuteBox = nullptr;
    QTableWidget* m_domainTable = nullptr;
    QPushButton* m_createButton = nullptr;
    QPushButton* m_restrictButton = nullptr;
    QPushButton* m_resetButton = nullptr;
    QPushButton* m_refreshButton = nullptr;
    QLabel* m_statusLabel = nullptr;
    bool m_busy = false;
};
