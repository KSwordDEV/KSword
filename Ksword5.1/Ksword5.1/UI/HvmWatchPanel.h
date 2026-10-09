#pragma once

// HvmWatchPanel：R-1 内存监视（首次访问归因）页。
//
// 它要回答的问题，是这套 ARK 里其它页都答不了的那一个。快照式检测能告诉用户
// 「SSDT / DriverObject / 回调 / 内核代码现在不对劲」，但答不出**是谁改的、
// 从哪条指令改的、第一次改发生在什么时候**——因为改动那一刻已经过去了。
// 这一页把问题换个方向问：盯住目标，等下一次访问，把那一刻的现场记下来。
//
// 界面上有三件事必须说清楚，因为它们都属于"读起来正确、理解起来会错"的那一类：
//
// - **监视单位是 4 KiB 物理页，不是用户选的那几个字节。** EPT 权限就是页粒度。
//   用户从 DriverObject->MajorFunction[14] 这样一个 8 字节字段建监视，装到硬件
//   上的仍然是那一页。所以请求范围与实际监视页必须并排显示，绝不能把它描述成
//   "8 字节硬件断点"。
// - **请求的访问类型与实际生效的可能不同。** EPT 不允许 W=1 而 R=0，所以"只监视
//   读"在硬件上一定连写也监视了。两栏都留着。
// - **这不是保护。** 命中后原访问照常完成；目标只要把自己那一页换个物理页就不在
//   被监视的页上了；DMA 根本不经过 CPU EPT。它是观察与归因，不是不可绕过的守卫。
//
// 还有一个容易被显示成反面的状态：命中了但事件环没接住。那时"没有事件"与"没被
// 访问过"在事件列表里长得一模一样，而结论正好相反，所以这一页用 watch 自己的
// hitCount / lastHitStatus 来区分，不依赖事件行是否存在。

#include <QHash>
#include <QWidget>

#include <functional>

// 进程归因结构要按值存进成员表，不能只前置声明。
#include "HvmControl.h"

class QLabel;
class QPushButton;
class QTableWidget;
class CodeEditorWidget;

// 监视表的列序。
//
// 放在头文件而不是某个 .cpp 的匿名命名空间里：铺表的那一半和导出证据的那一半
// 住在两个翻译单元（HvmWatchPanel.cpp 与 HvmWatchPanel.Evidence.cpp），而导出
// 要按编号列回取每行存着的快照。各留一份列序，某天插一列就会让导出静默错位——
// 那种错位不报错，只是把甲的证据写在乙的标题下面。
//
// 列的构成对应 issue #195 第十三节的表格规格。
enum HvmWatchColumn
{
    WatchColumnId = 0,
    WatchColumnTarget,
    WatchColumnRequestedRange,
    WatchColumnPage,
    WatchColumnRequestedAccess,
    WatchColumnEffectiveAccess,
    WatchColumnMode,
    WatchColumnState,
    WatchColumnHits,
    WatchColumnLastRip,
    WatchColumnModule,
    WatchColumnCount
};

class HvmWatchPanel final : public QWidget
{
public:
    explicit HvmWatchPanel(QWidget* parent = nullptr);

    // onBusyChanged：与其它 HVM 入口共用的串行化回调。
    // 安装与撤销都要独占驱动侧那把状态锁，别处的命令在飞时不能同时下手。
    std::function<void(bool)> onBusyChanged;

    // refreshAsync：后台读一次 watch 表。查询是阻塞 IOCTL，不能在 UI 线程直接调。
    void refreshAsync();

protected:
    void showEvent(QShowEvent* event) override;

private:
    void buildUi();
    void setBusy(bool busy);
    void updateEnabledState();
    // applyWatches：把一次快照铺进表格，并顺带做虚拟地址重映射检测。
    void applyWatches(const QVector<ksword::hvm::HvmWatchEntry>& watches);
    // describeWatchStateHere：状态文案，比协议翻译多一层常驻判据。
    //
    // 不改 ksword::hvm::describeWatchState 的签名：那一份是协议值到文字的纯
    // 翻译，别处也在用；"现在有没有人在看"是这一页才有的上下文。
    QString describeWatchStateHere(unsigned long state) const;
    // selectedWatch：当前选中行对应的快照，没选中返回 false。
    bool selectedWatch(ksword::hvm::HvmWatchEntry* entryOut) const;
    void showDetail(const ksword::hvm::HvmWatchEntry& entry);

    void startAdd();
    void startRearm();
    void startRemove();
    // startClear：清空整张表。
    //
    // 它走的是 EPT 规则的 CLEAR，所以**普通 EPT 规则会跟着一起没**——协议里
    // 没有"只清监视"这个操作。这个副作用必须在动手之前说给用户听，因此这里
    // 走破坏性操作确认，而不是一个普通的 Yes/No 询问。
    void startClear();
    // showHitEvent：去事件环里取回这条监视的命中事件并显示完整现场。
    //
    // 单独一个按钮而不是随选中行自动跑：读环是阻塞 IOCTL，而挂在选中行变化上
    // 意味着用方向键扫一遍表格就会发出几十次查询。它要拿的也不是面板上已经有
    // 的字段，而是只存在于事件行里的 qualification。
    void showHitEvent();
    void openWriterDisassembly();
    // openWriterMemory：按写入者的 RIP 读一段内存。
    //
    // 与「查看目标内存」读的**不是同一段**：那个读的是被监视的目标，这个读的
    // 是发起访问的那段代码本身。RIP 归不到任何已加载模块时，这一步和下面那个
    // 「查看 RIP 所在页」是仅有的两条能直接看那段来历不明代码的路。
    void openWriterMemory();
    // openWriterPage：把命中 RIP 所在的整页拿去反汇编。
    //
    // 与「查看写入者反汇编」的区别是范围：那个从 RIP 往前退 0x40 看一小段，
    // 这个看整页——地址不属于任何模块时，要判断这是一段什么东西（shellcode、
    // 被回收的池块、还是一段正常但没登记的代码），一小段看不出来。
    void openWriterPage();
    // openTargetMemory：在内存页里打开被监视的那一页。
    void openTargetMemory();
    // openWriterModule：在资源管理器里定位写入者所属的模块文件。
    void openWriterModule();
    // resolveHitProcess：把命中现场的 CR3 归到一个进程上。
    //
    // 单独一个按钮而不是随详情自动跑：它要 attach 遍历全部进程，几百次内核
    // 切换。挂在选中行变化上，光是用方向键扫一遍表格就会把机器压住 —— 而这
    // 一步的结果晚几秒出来不影响任何结论。
    void resolveHitProcess();
    void copyEvidence();
    // exportEvidence：把整张表写成一个文本文件。
    //
    // 与「复制证据」的区别不是范围而是用途：复制是为了贴进一条消息，导出是
    // 为了留档 —— 所以它写的是全部条目，包括尚未命中的那些（"这些目标被盯过
    // 且没被动"同样是结论），以及命中了但事件环没接住的那些。
    void exportEvidence();

    QLabel* m_hintLabel = nullptr;
    QTableWidget* m_table = nullptr;
    CodeEditorWidget* m_detail = nullptr;
    QLabel* m_statusLabel = nullptr;

    QPushButton* m_addButton = nullptr;
    QPushButton* m_rearmButton = nullptr;
    QPushButton* m_removeButton = nullptr;
    // 清空整张表，连带普通 EPT 规则。
    QPushButton* m_clearButton = nullptr;
    QPushButton* m_refreshButton = nullptr;
    // 取回命中事件（含只存在于事件行里的 qualification）。
    QPushButton* m_eventButton = nullptr;
    QPushButton* m_disassembleButton = nullptr;
    // 写入者所在地址的十六进制转储，以及它所在整页的反汇编。
    QPushButton* m_writerMemoryButton = nullptr;
    QPushButton* m_writerPageButton = nullptr;
    QPushButton* m_memoryButton = nullptr;
    QPushButton* m_moduleButton = nullptr;
    QPushButton* m_processButton = nullptr;
    QPushButton* m_copyButton = nullptr;
    QPushButton* m_exportButton = nullptr;

    // 按 CR3 缓存的进程归因。
    //
    // 按 CR3 而不是按 watchId：同一个地址空间被多条监视撞上时答案是同一个，
    // 而重复跑一次几百进程的遍历只是浪费。缓存是快照，所以显示时必须带上
    // "这是后来解析出来的"这层限定，不能说成命中那一刻的事实。
    QHash<quint64, ksword::hvm::HvmProcessAttribution> m_processAttribution;

    // m_residentActive：刷新那一刻至少有一个逻辑处理器处于 VMX non-root。
    //
    // 状态列要用它，理由是一条真实的伪造否定：规则表在常驻期间是冻结的，
    // 所以安装必然发生在常驻停着的时候，而驱动在安装那一刻就把状态置成
    // ARMED。装完还没启动常驻的这段时间里，如果界面照直显示"监视中 / 命中 0"，
    // 用户读到的是"这段时间没人动过它"——而那段时间根本没有人在看。
    bool m_residentActive = false;
    bool m_busy = false;
    bool m_queryInFlight = false;
};
