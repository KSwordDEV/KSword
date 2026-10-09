#pragma once

// HvmMemoryDialog：HVM（R-1 层）内存操作面板。
//
// R-1 读写复用普通内存页的十六进制/汇编编辑器。修改先暂存，只有显式应用
// 才会写回成功读取时绑定的地址、模式、PID 和 CR3；写入前比较原字节，写后回读。
//
// 所有 IOCTL 都在后台线程执行；写入额外受 HvmControl 的写权限门约束。

#include <QDialog>

#include <atomic>
#include <memory>

class QComboBox;
class QLabel;
class QLineEdit;
class QPushButton;
class QSpinBox;

namespace ks::ui
{
    class SnapshotWorkbenchWidget;
}

class HvmMemoryDialog final : public QDialog
{
    Q_OBJECT

public:
    explicit HvmMemoryDialog(QWidget* parent = nullptr);
    ~HvmMemoryDialog() override;
    void done(int result) override;

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
    // 虚拟地址默认按目标 PID 自动获取 CR3；非零自定义 CR3 优先且不传 PID。
    bool parseVirtualContext(unsigned long long* directoryBaseOut,
        unsigned long* processIdOut);
    // setBusy：进入或退出忙碌态，忙碌期间禁用全部动作按钮。
    void setBusy(bool busy);
    // 请求参数变更时清除缓存，禁止把旧编辑写向新的目标。
    void invalidateSnapshot();
    // 每个后台操作拥有独立取消令牌和序号，关闭窗口后丢弃旧回调。
    unsigned long long beginOperation();
    void cancelPendingOperation();
    // isVirtualMode：当前是否为虚拟地址模式。
    bool isVirtualMode() const;

    QComboBox* m_modeBox = nullptr;
    QLineEdit* m_addressEdit = nullptr;
    QLineEdit* m_processIdEdit = nullptr;
    QLineEdit* m_directoryBaseEdit = nullptr;
    QSpinBox* m_lengthBox = nullptr;
    ks::ui::SnapshotWorkbenchWidget* m_editor = nullptr;
    QPushButton* m_readButton = nullptr;
    QPushButton* m_writeButton = nullptr;
    QPushButton* m_discardButton = nullptr;
    QPushButton* m_translateButton = nullptr;
    QLabel* m_statusLabel = nullptr;
    QLabel* m_windowLabel = nullptr;
    bool m_busy = false;
    bool m_hasSnapshot = false;
    bool m_snapshotVirtualMode = false;
    unsigned long long m_snapshotAddress = 0;
    unsigned long long m_snapshotDirectoryBase = 0;
    unsigned long m_snapshotProcessId = 0;
    unsigned long long m_operationSerial = 0;
    std::shared_ptr<std::atomic_bool> m_cancelled;
};
