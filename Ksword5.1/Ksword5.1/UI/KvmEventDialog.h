#pragma once

// KvmEventDialog：HVM 实时事件流。
//
// 驱动侧的事件环一直在记录，但在此之前没有任何界面消费它——EPT 视图翻转、
// 规则命中、MSR 拦截全都是盲的。这个面板按固定间隔读取环里 afterSequence
// 之后的新事件，把它们追加到表里。
//
// 环是有界的：消费跟不上时驱动会报 droppedRows。那个数字必须显示出来，
// 否则用户看到的事件流会静默缺口。

#include <QDialog>

class QCheckBox;
class QLabel;
class QPushButton;
class QTableWidget;
class QTimer;

class KvmEventDialog final : public QDialog
{
    Q_OBJECT

public:
    explicit KvmEventDialog(QWidget* parent = nullptr);

private:
    // buildUi：构造控件树与信号连接。
    void buildUi();
    // poll：读取一次新事件并追加到表里。
    void poll();
    // trimRows：把表格裁剪到上限，避免长时间观察吃满内存。
    void trimRows();

    QTableWidget* m_eventTable = nullptr;
    QCheckBox* m_followCheck = nullptr;
    QPushButton* m_pauseButton = nullptr;
    QPushButton* m_clearButton = nullptr;
    QLabel* m_statusLabel = nullptr;
    QTimer* m_pollTimer = nullptr;
    // m_afterSequence：下一次只取这个序号之后的事件。
    unsigned long long m_afterSequence = 0;
    // m_droppedTotal：累计丢弃行数，跨多次轮询累加。
    unsigned long long m_droppedTotal = 0;
    bool m_paused = false;
    bool m_pollInFlight = false;
};
