#pragma once

// KvmMemoryDialog：KVM（R-1 层）内存操作面板。
//
// 由标题栏 KVM 按钮的右键菜单打开。它做的事只有一件：把 R-1 内存通道
// （私有页表窗口）暴露成可以手工驱动的读、写、翻译三个动作，并且如实显示
// 这一次访问到底走的是私有窗口还是退化后的 MmCopyMemory 路径——
// 后者仍能读到数据，但不再规避内核层 Hook，这个差别必须让人看得见。
//
// 所有 IOCTL 都在后台线程执行；写入额外受 KvmControl 的写权限门约束。

#include <QDialog>

class QCheckBox;
class QComboBox;
class QLabel;
class QLineEdit;
class QPlainTextEdit;
class QPushButton;
class QSpinBox;

class KvmMemoryDialog final : public QDialog
{
    Q_OBJECT

public:
    explicit KvmMemoryDialog(QWidget* parent = nullptr);

private:
    // buildUi：构造控件树与信号连接。
    void buildUi();
    // updateEnabledState：按当前模式、写权限与忙碌状态刷新控件可用性。
    void updateEnabledState();
    // startRead/startWrite/startTranslate：发起一次后台操作。
    void startRead();
    void startWrite();
    void startTranslate();
    // parseAddress：解析十六进制地址输入；失败时返回 false 并写状态行。
    bool parseAddress(const QLineEdit* field, unsigned long long* valueOut,
        const QString& fieldName);
    // setBusy：进入或退出忙碌态，忙碌期间禁用全部动作按钮。
    void setBusy(bool busy);
    // showHexDump：把读回的字节渲染成带偏移的十六进制视图。
    void showHexDump(unsigned long long baseAddress, const QByteArray& data);
    // isVirtualMode：当前是否为虚拟地址模式。
    bool isVirtualMode() const;

    QComboBox* m_modeBox = nullptr;
    QLineEdit* m_addressEdit = nullptr;
    QLineEdit* m_directoryBaseEdit = nullptr;
    QSpinBox* m_lengthBox = nullptr;
    QPlainTextEdit* m_dataView = nullptr;
    QLineEdit* m_writeEdit = nullptr;
    QPushButton* m_readButton = nullptr;
    QPushButton* m_writeButton = nullptr;
    QPushButton* m_translateButton = nullptr;
    QLabel* m_statusLabel = nullptr;
    QLabel* m_windowLabel = nullptr;
    bool m_busy = false;
};
