#include "HvmWatchPanel.h"

#include "KernelDisassemblyDialog.h"
#include "HvmControl.h"
// 安装表单与四个 ARK 页面共用同一份：两份表单会在"页粒度"和"请求访问与实际
// 访问"这两段说明上慢慢漂开，而那两段恰恰是这功能最容易被误解的地方。
#include "HvmWatchDialog.h"
// 命中事件的完整现场单独成窗：它比面板详情多一个只存在于事件行里的字段
// （qualification），而这一页已经接近文件体积上限，不适合再长。
#include "HvmWatchEventDialog.h"
#include "../Framework/DestructiveActionConfirmation.h"
#include "../Internationalization/LanguageManager.h"
#include "../theme.h"

#include <QApplication>
#include <QCheckBox>
#include <QClipboard>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QProcess>
#include <QTextStream>
#include <QComboBox>
#include <QDialog>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QGridLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QMetaObject>
#include <QPointer>
#include <QPushButton>
#include <QShowEvent>
#include <QTableWidget>
#include "StructuredFieldView.h"
#include <QVBoxLayout>

#include <thread>

namespace
{
    QString hex64(const unsigned long long value)
    {
        return QStringLiteral("0x%1")
            .arg(value, 16, 16, QLatin1Char('0')).toUpper();
    }

    QString text(const QString& source)
    {
        return ks::i18n::sourceText(source);
    }


}

HvmWatchPanel::HvmWatchPanel(QWidget* const parent)
    : QWidget(parent)
{
    buildUi();
    updateEnabledState();
}

void HvmWatchPanel::buildUi()
{
    auto* const rootLayout = new QVBoxLayout(this);
    rootLayout->setContentsMargins(6, 6, 6, 6);
    rootLayout->setSpacing(6);

    m_hintLabel = new QLabel(
        text(QStringLiteral("监视一个目标页的下一次访问，命中时记下访问者的现场，然后自动解除并让原访问正常继续 —— 常驻不会因此退出。这是观察与归因，不是保护：命中不阻止访问，监视单位是 4 KiB 页而不是你选的字节数，DMA 改写不经过 CPU 的 EPT，目标把自己那一页换个物理页就不在被监视的页上了。")),
        this);
    m_hintLabel->setWordWrap(true);
    rootLayout->addWidget(m_hintLabel);

    m_table = new QTableWidget(0, WatchColumnCount, this);
    m_table->setObjectName(QStringLiteral("HvmWatchTable"));
    m_table->setHorizontalHeaderLabels(QStringList()
        << text(QStringLiteral("编号"))
        << text(QStringLiteral("目标"))
        << text(QStringLiteral("请求范围"))
        << text(QStringLiteral("监视页"))
        << text(QStringLiteral("请求访问"))
        << text(QStringLiteral("实际访问"))
        << text(QStringLiteral("模式"))
        << text(QStringLiteral("状态"))
        << text(QStringLiteral("命中"))
        << text(QStringLiteral("最近 RIP"))
        << text(QStringLiteral("模块")));
    m_table->horizontalHeader()->setStretchLastSection(true);
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setSelectionMode(QAbstractItemView::SingleSelection);
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_table->setAlternatingRowColors(true);
    m_table->verticalHeader()->setVisible(false);
    rootLayout->addWidget(m_table, 3);

    auto* const buttons = new QGridLayout();
    m_addButton = new QPushButton(
        text(QStringLiteral("添加监视...")), this);
    m_rearmButton = new QPushButton(
        text(QStringLiteral("重新武装")), this);
    m_rearmButton->setToolTip(text(QStringLiteral("保留编号与累计命中次数，让这条监视再等下一次访问。已命中和已失效的都可以重新武装。")));
    m_removeButton = new QPushButton(
        text(QStringLiteral("移除")), this);
    m_removeButton->setToolTip(text(QStringLiteral("撤销选中的这一条监视并恢复该页权限。")));
    m_clearButton = new QPushButton(
        text(QStringLiteral("清空全部")), this);
    // 副作用写进悬停提示，而不是只写在确认框里：用户在按下去之前就该知道
    // 它清掉的不止是监视。
    m_clearButton->setToolTip(text(QStringLiteral("清空整张表。注意：监视与普通 EPT 规则住在同一张表里，协议没有“只清监视”这个操作，所以你装的分离视图规则会被一起清掉。")));
    m_refreshButton = new QPushButton(
        text(QStringLiteral("刷新")), this);
    m_refreshButton->setToolTip(text(QStringLiteral("重新读一次监视表，并顺带核对虚拟地址是否还指向武装时那一页。")));
    m_eventButton = new QPushButton(
        text(QStringLiteral("查看命中事件")), this);
    // 说清楚它与详情框的区别，否则看起来像是同一份东西换个窗口。
    m_eventButton->setToolTip(text(QStringLiteral("去事件环里取回这一次命中写进去的那一行。它比下方详情多一个字段：处理器给出的退出限定符（qualification）——那是“这次访问究竟是读、是写还是取指，页当时还剩哪些权限”的原始读数，监视记录里没有它。环会回绕，取不回来时会明说是丢了证据而不是没命中过。")));
    m_disassembleButton = new QPushButton(
        text(QStringLiteral("查看写入者反汇编")), this);
    m_disassembleButton->setToolTip(text(QStringLiteral("从命中 RIP 往前退 0x40 开始反汇编。往前退是因为 RIP 指的是尚未完成的那条指令，只从它开始看不到前面几条在算什么地址。")));
    m_writerMemoryButton = new QPushButton(
        text(QStringLiteral("查看写入者内存")), this);
    // 与「查看目标内存」读的不是同一段，提示里必须把这一点分开。
    m_writerMemoryButton->setToolTip(text(QStringLiteral("按命中 RIP 读一段内存。读的是发起访问的那段代码本身，不是被监视的目标——RIP 归不到任何已加载模块时，这是直接看那段代码的入口之一。")));
    m_writerPageButton = new QPushButton(
        text(QStringLiteral("查看 RIP 所在页")), this);
    m_writerPageButton->setToolTip(text(QStringLiteral("把命中 RIP 所在的整页拿去反汇编。要判断一段不属于任何模块的代码是什么东西，一小段看不出来，整页才能看出它有没有函数序言、是不是被回收的池块。")));
    m_memoryButton = new QPushButton(
        text(QStringLiteral("查看目标内存")), this);
    m_memoryButton->setToolTip(text(QStringLiteral("按被监视的那一页读一段内存。这是**命中之后**的采样，不是命中那一刻的值——EPT violation 发生在写指令退休之前，所以这里读到的可能已经包含那次写入，也可能还包含之后的更多次修改。")));
    m_moduleButton = new QPushButton(
        text(QStringLiteral("查看模块")), this);
    m_moduleButton->setToolTip(text(QStringLiteral("在资源管理器里定位命中 RIP 所属的内核模块文件。RIP 不落在任何已加载模块里时这个按钮不可用。")));
    m_processButton = new QPushButton(
        text(QStringLiteral("解析命中进程")), this);
    m_processButton->setToolTip(text(QStringLiteral("把命中现场记下的 CR3 归到一个进程上。它要逐个进程读回页目录基址，所以是一次显式操作而不是随选中行自动跑。结果是后处理推断：进程可能已经退出、PID 可能已经被回收。")));
    m_copyButton = new QPushButton(
        text(QStringLiteral("复制证据")), this);
    m_exportButton = new QPushButton(
        text(QStringLiteral("导出全部证据...")), this);
    m_exportButton->setToolTip(text(QStringLiteral("把当前监视表里每一条的目标、命中现场与归因写成一个文本文件。已命中但事件环没接住证据的那几条同样会写进去，并标注出来。")));
    // 第一行是监视自身的生命周期，第二行是拿到现场之后的去向。
    buttons->addWidget(m_addButton, 0, 0);
    buttons->addWidget(m_rearmButton, 0, 1);
    buttons->addWidget(m_removeButton, 0, 2);
    buttons->addWidget(m_clearButton, 0, 3);
    buttons->addWidget(m_refreshButton, 0, 4);
    buttons->addWidget(m_copyButton, 0, 5);
    buttons->addWidget(m_eventButton, 1, 0);
    buttons->addWidget(m_disassembleButton, 1, 1);
    buttons->addWidget(m_memoryButton, 1, 2);
    buttons->addWidget(m_moduleButton, 1, 3);
    buttons->addWidget(m_processButton, 1, 4);
    buttons->addWidget(m_exportButton, 1, 5);
    // 第三行专给"RIP 归不到模块"那条路：整页反汇编与写入者内存都只服务它。
    buttons->addWidget(m_writerMemoryButton, 2, 0);
    buttons->addWidget(m_writerPageButton, 2, 1);
    rootLayout->addLayout(buttons);

    m_detail = new ks::ui::StructuredFieldView(this);
    m_detail->setDocument(ks::ui::FieldDocument{}.note(
        text(QStringLiteral("选中一条监视查看它的完整现场与归因。"))));
    rootLayout->addWidget(m_detail, 2);

    m_statusLabel = new QLabel(QString(), this);
    m_statusLabel->setWordWrap(true);
    rootLayout->addWidget(m_statusLabel);

    connect(m_addButton, &QPushButton::clicked, this, [this]() { startAdd(); });
    connect(m_rearmButton, &QPushButton::clicked, this, [this]() { startRearm(); });
    connect(m_removeButton, &QPushButton::clicked, this, [this]() { startRemove(); });
    connect(m_clearButton, &QPushButton::clicked, this, [this]() { startClear(); });
    connect(m_refreshButton, &QPushButton::clicked, this, [this]() { refreshAsync(); });
    connect(m_eventButton, &QPushButton::clicked, this, [this]() { showHitEvent(); });
    connect(m_disassembleButton, &QPushButton::clicked, this, [this]() {
        openWriterDisassembly();
    });
    connect(m_writerMemoryButton, &QPushButton::clicked, this, [this]() {
        openWriterMemory();
    });
    connect(m_writerPageButton, &QPushButton::clicked, this, [this]() {
        openWriterPage();
    });
    connect(m_memoryButton, &QPushButton::clicked, this, [this]() {
        openTargetMemory();
    });
    connect(m_moduleButton, &QPushButton::clicked, this, [this]() {
        openWriterModule();
    });
    connect(m_processButton, &QPushButton::clicked, this, [this]() {
        resolveHitProcess();
    });
    connect(m_copyButton, &QPushButton::clicked, this, [this]() { copyEvidence(); });
    connect(m_exportButton, &QPushButton::clicked, this, [this]() { exportEvidence(); });
    connect(m_table, &QTableWidget::itemSelectionChanged, this, [this]() {
        ksword::hvm::HvmWatchEntry entry;
        if (selectedWatch(&entry))
        {
            showDetail(entry);
        }
        updateEnabledState();
    });
}

void HvmWatchPanel::showEvent(QShowEvent* const event)
{
    QWidget::showEvent(event);
    refreshAsync();
}

void HvmWatchPanel::setBusy(const bool busy)
{
    m_busy = busy;
    updateEnabledState();
    if (onBusyChanged)
    {
        onBusyChanged(busy);
    }
}

void HvmWatchPanel::updateEnabledState()
{
    const bool writeAllowed = ksword::hvm::isWriteAccessEnabled();
    const QString writeHint = writeAllowed
        ? QString()
        : text(QStringLiteral("R-1 写权限未开启：在 HVM 按钮右键菜单中开启后才能安装或撤销监视"));
    ksword::hvm::HvmWatchEntry entry;
    const bool hasSelection = selectedWatch(&entry);

    if (m_addButton != nullptr)
    {
        m_addButton->setEnabled(writeAllowed && !m_busy);
        m_addButton->setToolTip(writeHint);
    }
    if (m_rearmButton != nullptr)
    {
        m_rearmButton->setEnabled(writeAllowed && !m_busy && hasSelection);
        m_rearmButton->setToolTip(writeHint);
    }
    if (m_removeButton != nullptr)
    {
        m_removeButton->setEnabled(writeAllowed && !m_busy && hasSelection);
        m_removeButton->setToolTip(writeHint);
    }
    if (m_clearButton != nullptr)
    {
        // 表是空的就没有可清的；写权限门与其它破坏性操作同一道。
        m_clearButton->setEnabled(writeAllowed && !m_busy &&
            m_table != nullptr && m_table->rowCount() > 0);
        if (!writeAllowed)
        {
            m_clearButton->setToolTip(writeHint);
        }
    }
    if (m_refreshButton != nullptr)
    {
        m_refreshButton->setEnabled(!m_busy);
    }
    // 反汇编与复制证据只在真的有一次命中之后才有东西可看。
    const bool hasHit = hasSelection && entry.hitCount != 0UL;
    if (m_eventButton != nullptr)
    {
        /*
         * 命中过就可以点，哪怕证据已经丢了。
         *
         * 按 lastHitStatus == PUBLISHED 去禁用它才是错的：证据丢失那一态正是
         * 用户最需要一句明确解释的时候，而把按钮灰掉等于让界面在那一刻沉默。
         */
        m_eventButton->setEnabled(!m_busy && hasHit);
    }
    if (m_disassembleButton != nullptr)
    {
        m_disassembleButton->setEnabled(!m_busy && hasHit && entry.lastHitRip != 0ULL);
    }
    // 这两个与反汇编同一条判据：有 RIP 就能看，不要求归得到模块——
    // 归不到模块恰恰是最需要它们的时候。
    if (m_writerMemoryButton != nullptr)
    {
        m_writerMemoryButton->setEnabled(
            !m_busy && hasHit && entry.lastHitRip != 0ULL);
    }
    if (m_writerPageButton != nullptr)
    {
        m_writerPageButton->setEnabled(
            !m_busy && hasHit && entry.lastHitRip != 0ULL);
    }
    if (m_memoryButton != nullptr)
    {
        // 目标内存不要求命中：还没命中的目标同样值得看一眼当前内容。
        m_memoryButton->setEnabled(!m_busy && hasSelection &&
            entry.physicalPage != 0ULL);
    }
    if (m_moduleButton != nullptr)
    {
        /*
         * 只有"比过一遍、确实不在任何模块里"才该把按钮灰掉。
         *
         * 归因**失败**时不能灰：那时我们并不知道有没有模块可看，灰掉等于
         * 把一次没跑起来的查询显示成一条结论。留着可点，点了会给出失败原因。
         */
        const ksword::hvm::HvmWatchAttribution attribution = hasHit
            ? ksword::hvm::attributeKernelAddress(entry.lastHitRip)
            : ksword::hvm::HvmWatchAttribution();
        m_moduleButton->setEnabled(!m_busy && hasHit &&
            entry.lastHitRip != 0ULL &&
            attribution.kind != ksword::hvm::HvmWatchAttributionKind::NotFound);
    }
    if (m_processButton != nullptr)
    {
        m_processButton->setEnabled(!m_busy && hasHit && entry.lastHitCr3 != 0ULL);
    }
    if (m_copyButton != nullptr)
    {
        m_copyButton->setEnabled(hasSelection);
    }
    if (m_exportButton != nullptr)
    {
        // 导出不需要选中任何一条：它写的是整张表。
        m_exportButton->setEnabled(m_table != nullptr && m_table->rowCount() > 0);
    }
}

bool HvmWatchPanel::selectedWatch(
    ksword::hvm::HvmWatchEntry* const entryOut) const
{
    if (m_table == nullptr)
    {
        return false;
    }
    const int row = m_table->currentRow();
    if (row < 0 || m_table->item(row, WatchColumnId) == nullptr)
    {
        return false;
    }
    const QVariant stored =
        m_table->item(row, WatchColumnId)->data(Qt::UserRole);
    if (!stored.isValid())
    {
        return false;
    }
    // 整条快照存在行上而不是逐列反解析：表格里的每一列都是给人读的文字，
    // 从文字反推回数值会在第一个本地化的词上出错。
    *entryOut = stored.value<ksword::hvm::HvmWatchEntry>();
    return true;
}

void HvmWatchPanel::refreshAsync()
{
    if (m_queryInFlight || m_busy)
    {
        return;
    }
    m_queryInFlight = true;
    QPointer<HvmWatchPanel> safeThis(this);
    std::thread([safeThis]() {
        const ksword::hvm::HvmWatchResult result = ksword::hvm::listWatches();
        /*
         * 顺手在同一次后台跳里读一次常驻状态。
         *
         * 它决定 ARMED 该显示成"监视中"还是"已武装但还没开始观察"，而这两句话
         * 在"命中 0"旁边会被读成相反的结论。放在同一跳里而不是另起一次：两次
         * 查询之间常驻可以变，那时表格与状态灯会互相矛盾。
         */
        const ksword::hvm::HvmState state = ksword::hvm::queryState();
        if (safeThis == nullptr)
        {
            return;
        }
        QMetaObject::invokeMethod(
            safeThis,
            [safeThis, result, state]() {
                if (safeThis == nullptr)
                {
                    return;
                }
                safeThis->m_queryInFlight = false;
                safeThis->m_residentActive = state.residentActive;
                if (!result.ok)
                {
                    safeThis->m_statusLabel->setText(result.message);
                    return;
                }
                safeThis->applyWatches(result.watches);
                // 常驻没跑时把这句话跟在条数后面：表里每一行的"命中 0"
                // 在这一刻都不构成"没人动过"。
                safeThis->m_statusLabel->setText(state.residentActive
                    ? text(QStringLiteral("当前有 %1 条内存监视。"))
                        .arg(result.watchCount)
                    : text(QStringLiteral("当前有 %1 条内存监视。常驻没有在运行，所以这些监视此刻一条都没有在观察——表里的“命中 0”不代表目标没被访问过。"))
                        .arg(result.watchCount));
            },
            Qt::QueuedConnection);
    }).detach();
}

/*
 * describeWatchStateHere：状态文案，比协议翻译多一层"现在有没有人在看"。
 *
 * ARMED 只说明这条监视已经装进规则表，不说明它正在观察。规则表在常驻期间
 * 冻结，所以安装**必然**发生在常驻停着的时候，而驱动在那一刻就置 ARMED。
 * 照直显示"监视中"，用户在启动常驻之前看到的就是"监视中 / 命中 0"——他会
 * 据此得出"这段时间没人动过它"，而那段时间根本没有人在看。这正是这个功能
 * 最不能给出的那一类答案。
 *
 * 入参 state：协议状态值 KSWORD_ARK_HVM_EPT_WATCH_STATE_*。
 * 返回：可直接显示的文字。
 */
QString HvmWatchPanel::describeWatchStateHere(const unsigned long state) const
{
    if (state == KSWORD_ARK_HVM_EPT_WATCH_STATE_ARMED && !m_residentActive)
    {
        return text(QStringLiteral("已武装（常驻未运行，还没有开始观察）"));
    }
    return ksword::hvm::describeWatchState(state);
}

void HvmWatchPanel::applyWatches(
    const QVector<ksword::hvm::HvmWatchEntry>& watches)
{
    m_table->setRowCount(watches.size());
    for (int row = 0; row < watches.size(); ++row)
    {
        const ksword::hvm::HvmWatchEntry& entry = watches.at(row);
        const auto setCell = [this, row](const int column, const QString& value) {
            auto* const item = new QTableWidgetItem(value);
            item->setToolTip(value);
            m_table->setItem(row, column, item);
            return item;
        };
        auto* const idItem = setCell(
            WatchColumnId, QString::number(entry.watchId));
        idItem->setData(Qt::UserRole, QVariant::fromValue(entry));
        /*
         * 目标列优先显示人话标签。
         *
         * 标签是从 SSDT / DriverObject / 回调这些页面右键进来时带上的那句描述
         * （例如"\Driver\Foo MajorFunction[IRP_MJ_DEVICE_CONTROL]"）。它存在
         * R3 这一侧，协议里没有这个字段。
         *
         * 地址不因此消失，而是进了这一格的悬停提示：标签说的是"我以为我在盯
         * 什么"，地址说的是"实际盯的是哪里"，两者对不上正是要看出来的东西。
         */
        const QString targetAddress =
            entry.addressKind == KSWORD_ARK_HVM_WATCH_ADDRESS_VIRTUAL
                ? text(QStringLiteral("虚拟 %1")).arg(hex64(entry.requestedAddress))
                : text(QStringLiteral("物理 %1")).arg(hex64(entry.requestedAddress));
        const QString targetLabel = ksword::hvm::watchLabel(entry);
        auto* const targetItem = setCell(WatchColumnTarget,
            targetLabel.isEmpty() ? targetAddress : targetLabel);
        targetItem->setToolTip(targetLabel.isEmpty()
            ? targetAddress
            : QStringLiteral("%1\n%2").arg(targetLabel).arg(targetAddress));
        setCell(WatchColumnRequestedRange,
            text(QStringLiteral("%1 字节")).arg(entry.requestedLength));
        // 监视页那一栏把 4096 明写出来：两栏并排才说得清粒度差别。
        setCell(WatchColumnPage,
            text(QStringLiteral("%1（4096 字节）")).arg(hex64(entry.physicalPage)));
        setCell(WatchColumnRequestedAccess,
            ksword::hvm::describeWatchAccess(entry.requestedAccess));
        setCell(WatchColumnEffectiveAccess,
            ksword::hvm::describeWatchAccess(entry.effectiveAccess));
        setCell(WatchColumnMode, text(QStringLiteral("首次访问")));
        setCell(WatchColumnState,
            describeWatchStateHere(entry.state));
        // 命中列同时承载"证据在不在"：命中过但事件丢了，与从未命中，
        // 在事件列表里长得一样而结论相反。
        setCell(WatchColumnHits,
            entry.lastHitStatus == KSWORD_ARK_HVM_EPT_WATCH_HIT_EVENT_LOST
                ? text(QStringLiteral("%1（事件已丢失）")).arg(entry.hitCount)
                : QString::number(entry.hitCount));
        setCell(WatchColumnLastRip,
            entry.lastHitRip != 0ULL ? hex64(entry.lastHitRip) : QStringLiteral("-"));
        QString moduleText = QStringLiteral("-");
        if (entry.lastHitRip != 0ULL)
        {
            const ksword::hvm::HvmWatchAttribution attribution =
                ksword::hvm::attributeKernelAddress(entry.lastHitRip);
            // 有导出符号就用 `module!Symbol+0x..`，没有才退回 `module.sys+0xRVA`。
            // 两种都是真话，区别只是精度；编一个最近的名字出来才是错的。
            //
            // 归因失败与"确实不在任何模块里"在这一列也必须分开：一格写着
            // "未知可执行区域"会被当成一条可疑读数去追，而它可能只是这次
            // 没读到模块表。
            moduleText = attribution.kind ==
                    ksword::hvm::HvmWatchAttributionKind::Failed
                ? text(QStringLiteral("归因未跑起来"))
                : !attribution.resolved
                ? text(QStringLiteral("未知可执行区域"))
                : attribution.symbolName.isEmpty()
                    ? QStringLiteral("%1+0x%2")
                        .arg(attribution.moduleName)
                        .arg(attribution.relativeAddress, 0, 16)
                    : QStringLiteral("%1!%2+0x%3")
                        .arg(attribution.moduleName)
                        .arg(attribution.symbolName)
                        .arg(attribution.symbolOffset, 0, 16);
        }
        setCell(WatchColumnModule, moduleText);
    }
    m_table->resizeColumnsToContents();
    updateEnabledState();
}

void HvmWatchPanel::showDetail(const ksword::hvm::HvmWatchEntry& entry)
{
    ks::ui::FieldDocument document;
    document.section(QStringLiteral("目标"));
    // 标签存在 R3 这一侧（协议里没有这个字段），从别的页面右键进来时带上。
    // 没有标签时明说原因，不留一行空白让人以为是读失败了。
    const QString label = ksword::hvm::watchLabel(entry);
    document.field(QStringLiteral("标签"), QStringLiteral("%1")
        .arg(label.isEmpty()
            ? text(QStringLiteral("（未命名，在这一页直接添加的监视没有标签）"))
            : label));
    document.field(QStringLiteral("请求地址"), QStringLiteral("%1")
        .arg(hex64(entry.requestedAddress)));
    document.field(QStringLiteral("请求长度"), QStringLiteral("%1 字节")
        .arg(entry.requestedLength));
    document.field(QStringLiteral("实际监视页"), QStringLiteral("%1，4096 字节")
        .arg(hex64(entry.physicalPage)));
    /*
     * 页内偏移单独列一行。
     *
     * 它是请求地址落在被监视那一页的第几个字节。不列出来，请求地址与监视页
     * 摆在一起看着像同一回事；列出来，用户一眼能看出硬件实际盯的范围比自己
     * 选的宽了多少，以及自己关心的那几个字节坐落在哪。
     */
    document.field(QStringLiteral("页内偏移"), QStringLiteral("+0x%1")
        .arg(entry.requestedAddress & 0xFFFULL, 0, 16));
    document.field(QStringLiteral("请求访问"), QStringLiteral("%1")
        .arg(ksword::hvm::describeWatchAccess(entry.requestedAccess)));
    document.field(QStringLiteral("实际访问"), QStringLiteral("%1")
        .arg(ksword::hvm::describeWatchAccess(entry.effectiveAccess)));
    document.field(QStringLiteral("模式"), QStringLiteral("首次访问"));


    // 虚拟地址重映射检测。
    //
    // 这条监视绑死在武装那一刻解析出来的物理页上，不会跟着 VA 的新映射走。
    // 检测不出来时**不能**继续显示成"正在监视该虚拟地址"——那是一句读起来
    // 正确、实际可能完全不成立的话。
    if (entry.addressKind == KSWORD_ARK_HVM_WATCH_ADDRESS_VIRTUAL &&
        entry.requestedAddress != 0ULL)
    {
        const ksword::hvm::HvmMemoryResult current =
            ksword::hvm::translate(0, entry.requestedAddress);
        if (current.ok && current.physicalAddress != 0ULL)
        {
            const unsigned long long currentPage =
                current.physicalAddress & ~0xFFFULL;
            document.note((currentPage == entry.physicalPage
                ? text(QStringLiteral("映射核对        当前虚拟地址仍然落在被监视的那一页上。"))
                : text(QStringLiteral("映射核对        **当前虚拟地址已经指向 %1，与武装时的 %2 不是同一页。这条监视仍然盯着武装时那一页，不再对应该虚拟地址。**"))
                    .arg(hex64(currentPage))
                    .arg(hex64(entry.physicalPage))));
        }
        else
        {
            document.field(QStringLiteral("映射核对"), QStringLiteral("当前翻译不出物理页，无法核对该虚拟地址是否还指向被监视的那一页。"));
        }

    }

    document.section(QStringLiteral("命中"));
    if (entry.hitCount == 0UL)
    {
        document.field(QStringLiteral(""), QStringLiteral("尚未命中。"));
    }
    else
    {
        document.field(QStringLiteral("累计命中"), QStringLiteral("%1 次")
            .arg(entry.hitCount));
        // 命中时刻。驱动记的是性能计数，不是墙钟——换算出来的时间必须带上
        // "这是换算来的"，否则等于声称记下了一件没有记过的事。
        document.field(QStringLiteral("命中时间"), QStringLiteral("%1")
            .arg(ksword::hvm::describeWatchHitTime(entry.lastHitTimestamp)));
        document.field(QStringLiteral("事件序号"), QStringLiteral("%1")
            .arg(entry.lastHitSequence));
        document.field(QStringLiteral("证据状态"), QStringLiteral("%1")
            .arg(entry.lastHitStatus ==
                    KSWORD_ARK_HVM_EPT_WATCH_HIT_PUBLISHED
                ? text(QStringLiteral("事件已发布"))
                : text(QStringLiteral("已命中，但事件环没接住这条证据"))));
        document.field(QStringLiteral("处理器"), QStringLiteral("%1:%2")
            .arg(entry.lastHitProcessorGroup)
            .arg(entry.lastHitProcessorNumber));
        document.field(QStringLiteral("客户物理地址"), QStringLiteral("%1")
            .arg(hex64(entry.lastHitGuestPhysicalAddress)));
        document.field(QStringLiteral("客户线性地址"), QStringLiteral("%1")
            .arg(entry.lastHitGuestLinearValid
                ? hex64(entry.lastHitGuestLinearAddress)
                : text(QStringLiteral("处理器未报告"))));
        /*
         * 范围命中有两种"答不了"，都不能默认成"不在范围内"：
         *
         * - 处理器没给有效的客户线性地址；
         * - 这条监视是按**物理**地址建的。那时请求地址是一个物理地址，而命中
         *   时拿来比的是客户线性地址——两个地址空间不可比，比出来的结果无论
         *   是真是假都没有意义。说成"否"等于给了一个看起来是结论的假答案。
         */
        document.field(QStringLiteral("落在请求范围内"), QStringLiteral("%1")
            .arg(!entry.lastHitGuestLinearValid
                ? text(QStringLiteral("无法判断（没有有效的客户线性地址）"))
                : entry.addressKind != KSWORD_ARK_HVM_WATCH_ADDRESS_VIRTUAL
                    ? text(QStringLiteral("无法判断（这条监视按物理地址建立，而处理器报告的是线性地址，两者不在同一个地址空间）"))
                    : entry.lastHitRangeMatch
                        ? text(QStringLiteral("是"))
                        : text(QStringLiteral("否，落在同一页的其它偏移上"))));
        document.field(QStringLiteral("RIP"), QStringLiteral("%1")
            .arg(hex64(entry.lastHitRip)));
        document.field(QStringLiteral("RSP"), QStringLiteral("%1")
            .arg(hex64(entry.lastHitRsp)));
        document.field(QStringLiteral("CR3"), QStringLiteral("%1")
            .arg(entry.lastHitCr3 != 0ULL
                ? hex64(entry.lastHitCr3)
                : text(QStringLiteral("未采集"))));

        document.section(QStringLiteral("归因"));
        const ksword::hvm::HvmWatchAttribution attribution =
            ksword::hvm::attributeKernelAddress(entry.lastHitRip);
        if (attribution.resolved)
        {
            document.field(QStringLiteral("模块"), QStringLiteral("%1")
                .arg(attribution.moduleName));
            document.field(QStringLiteral("模块路径"), QStringLiteral("%1")
                .arg(attribution.modulePath));
            document.field(QStringLiteral("模块内偏移"), QStringLiteral("+0x%1")
                .arg(attribution.relativeAddress, 0, 16));
            // 符号只来自导出表：它答不出静态函数，所以"没有符号"不等于"这个
            // 地址不在函数里"，只等于"它前面没有导出符号"。这句差别要说出来，
            // 否则空符号会被当成异常信号。
            document.note((attribution.symbolName.isEmpty()
                ? text(QStringLiteral("  符号            该地址之前没有导出符号（只解析导出表，不解析 PDB；静态函数本就不在其中）。"))
                : text(QStringLiteral("  符号            %1!%2+0x%3"))
                    .arg(attribution.moduleName)
                    .arg(attribution.symbolName)
                    .arg(attribution.symbolOffset, 0, 16)));
        }
        else if (attribution.kind ==
            ksword::hvm::HvmWatchAttributionKind::Failed)
        {
            /*
             * 模块表没读出来。
             *
             * 这一句**不能**写成"不属于任何已加载模块"——那是一条没有根据的
             * 结论。两者在界面上只差一句话，但会把人送去查两个相反的方向：
             * 一个说"这段代码来历不明，接着查它"，一个说"这次没问出来，再试一次"。
             */
            document.field(QStringLiteral("模块"), QStringLiteral("这次模块归因没有跑起来（读不到系统模块表），所以答不出这个 RIP 属不属于已加载模块。这不是“未知可执行区域”。"));
            document.field(QStringLiteral(""), QStringLiteral("刷新后重试；仍然失败时用“查看写入者反汇编”直接看那一段代码。"));
        }
        else
        {
            // 归不到模块是一条结论而不是失败：它本身就是可疑的读数。
            document.field(QStringLiteral("模块"), QStringLiteral("未知可执行区域 —— 这个 RIP 不落在任何已加载内核模块的映像范围内。"));
            document.field(QStringLiteral(""), QStringLiteral("用“查看写入者反汇编”“查看写入者内存”“查看 RIP 所在页”直接看那一段代码。"));
        }
        /*
         * 进程归因是后处理，而且是显式的一步。
         *
         * 没解析过时显示"还没解析"，不显示"未知"——后者把"没问"和"问过了没有"
         * 说成同一件事，而这两句话里只有后一句是结论。
         */
        if (entry.lastHitCr3 == 0ULL)
        {
            document.field(QStringLiteral("进程"), QStringLiteral("命中现场没有记下地址空间，无从归因。"));
        }
        else
        {
            const auto cached = m_processAttribution.constFind(entry.lastHitCr3);
            document.note((cached != m_processAttribution.constEnd()
                ? text(QStringLiteral("  进程            %1"))
                    .arg(ksword::hvm::describeProcessAttribution(*cached))
                : text(QStringLiteral("  进程            尚未解析。点“解析命中进程”按 CR3 反查——这一步要逐个进程读页目录基址，所以不随选中行自动跑。"))));
        }
    }

    document.section(QStringLiteral("HVM"));
    document.field(QStringLiteral("监视状态"), QStringLiteral("%1")
        .arg(describeWatchStateHere(entry.state)));
    document.field(QStringLiteral("武装代次"), QStringLiteral("%1")
        .arg(entry.armedGeneration));
    /*
     * 常驻没跑时，"未命中"这三个字不成立。
     *
     * 监视是"某段时间里有人在看"的断言；常驻停着的时候没有任何处理器加载着
     * 这套 EPT 指针，也就不会产生任何退出。此时把"命中 0"原样摆出来而不说明，
     * 用户读到的就是一条凭空的否定结论。
     */
    if (!m_residentActive)
    {
        document.field(QStringLiteral("是否在观察"), QStringLiteral("否 —— 常驻没有在运行。这条监视此刻不会产生任何命中，上面的命中计数只覆盖它武装过且常驻在跑的那些时间段。"));
    }
    // REARM 保留累计命中与上一轮的现场，所以现场可能属于更早的某一轮。
    if (entry.hitCount != 0UL &&
        entry.state == KSWORD_ARK_HVM_EPT_WATCH_STATE_ARMED)
    {
        document.field(QStringLiteral("现场归属"), QStringLiteral("这条监视已经重新武装过；上面那份命中现场属于**之前**某一轮，不是当前这一轮（当前这一轮还没有命中）。"));
    }
    m_detail->setDocument(document);
}

void HvmWatchPanel::startAdd()
{
    HvmWatchAddDialog dialog(this);
    if (dialog.exec() != QDialog::Accepted)
    {
        return;
    }
    if (!dialog.addressValid())
    {
        m_statusLabel->setText(
            text(QStringLiteral("地址不是合法的非零十六进制数。")));
        return;
    }
    const ksword::hvm::HvmWatchTarget target = dialog.target();
    if (target.access == 0UL)
    {
        m_statusLabel->setText(
            text(QStringLiteral("请至少选择一种要监视的访问类型。")));
        return;
    }
    setBusy(true);
    m_statusLabel->setText(text(QStringLiteral("正在安装监视...")));
    QPointer<HvmWatchPanel> safeThis(this);
    std::thread([safeThis, target]() {
        const ksword::hvm::HvmWatchResult result =
            ksword::hvm::addWatch(target);
        if (safeThis == nullptr)
        {
            return;
        }
        QMetaObject::invokeMethod(
            safeThis,
            [safeThis, result]() {
                if (safeThis == nullptr)
                {
                    return;
                }
                safeThis->setBusy(false);
                safeThis->m_statusLabel->setText(result.message);
                safeThis->refreshAsync();
            },
            Qt::QueuedConnection);
    }).detach();
}

void HvmWatchPanel::startRearm()
{
    ksword::hvm::HvmWatchEntry entry;
    if (!selectedWatch(&entry))
    {
        m_statusLabel->setText(
            text(QStringLiteral("请先在表中选择一条监视。")));
        return;
    }
    setBusy(true);
    m_statusLabel->setText(text(QStringLiteral("正在重新武装...")));
    const unsigned long watchId = entry.watchId;
    QPointer<HvmWatchPanel> safeThis(this);
    std::thread([safeThis, watchId]() {
        const ksword::hvm::HvmWatchResult result =
            ksword::hvm::rearmWatch(watchId);
        if (safeThis == nullptr)
        {
            return;
        }
        QMetaObject::invokeMethod(
            safeThis,
            [safeThis, result]() {
                if (safeThis == nullptr)
                {
                    return;
                }
                safeThis->setBusy(false);
                safeThis->m_statusLabel->setText(result.message);
                safeThis->refreshAsync();
            },
            Qt::QueuedConnection);
    }).detach();
}

void HvmWatchPanel::startRemove()
{
    ksword::hvm::HvmWatchEntry entry;
    if (!selectedWatch(&entry))
    {
        m_statusLabel->setText(
            text(QStringLiteral("请先在表中选择一条监视。")));
        return;
    }
    setBusy(true);
    m_statusLabel->setText(text(QStringLiteral("正在移除监视...")));
    const unsigned long watchId = entry.watchId;
    QPointer<HvmWatchPanel> safeThis(this);
    std::thread([safeThis, watchId]() {
        const ksword::hvm::HvmWatchResult result =
            ksword::hvm::removeWatch(watchId);
        if (safeThis == nullptr)
        {
            return;
        }
        QMetaObject::invokeMethod(
            safeThis,
            [safeThis, result, watchId]() {
                if (safeThis == nullptr)
                {
                    return;
                }
                safeThis->setBusy(false);
                // 监视没了，它的标签也不该留着：watchId 会被驱动回收再发给
                // 另一条监视，留着就会让那一条顶着这一条的描述显示出来。
                if (result.ok)
                {
                    ksword::hvm::forgetWatchLabel(watchId);
                }
                safeThis->m_statusLabel->setText(result.message);
                safeThis->refreshAsync();
            },
            Qt::QueuedConnection);
    }).detach();
}

/*
 * startClear：清空整张表。
 *
 * 这个操作的副作用比它的名字大：协议里没有"只清监视"，CLEAR 清的是整张 EPT
 * 规则表，所以用户装的分离视图规则会跟着一起没。所以确认框里写的是实际会发生
 * 的事，而不是"确定要清空监视吗"。
 */
void HvmWatchPanel::startClear()
{
    if (m_table == nullptr || m_table->rowCount() == 0)
    {
        return;
    }
    if (!ks::ui::confirmDestructiveAction(
            this,
            QStringLiteral("HvmWatchClearAll"),
            text(QStringLiteral("清空内存监视与 EPT 规则")),
            text(QStringLiteral("整张 EPT 规则表（当前 %1 条监视）"))
                .arg(m_table->rowCount()),
            text(QStringLiteral("监视与普通 EPT 规则住在同一张表里，协议没有“只清监视”这个操作，所以你装的分离视图规则会被一起清掉，被它们占住的页权限也会一并恢复。已经命中过的监视连同它们保留的现场一起消失，想留证据请先“导出全部证据”。"))))
    {
        return;
    }
    setBusy(true);
    m_statusLabel->setText(text(QStringLiteral("正在清空...")));
    QPointer<HvmWatchPanel> safeThis(this);
    std::thread([safeThis]() {
        const ksword::hvm::HvmWatchResult result =
            ksword::hvm::clearWatches();
        if (safeThis == nullptr)
        {
            return;
        }
        QMetaObject::invokeMethod(
            safeThis,
            [safeThis, result]() {
                if (safeThis == nullptr)
                {
                    return;
                }
                safeThis->setBusy(false);
                // 表清空了，本机存的那些标签就都成了无主的：留着只会在下一批
                // 监视拿到相同编号时冒出来。
                if (result.ok)
                {
                    ksword::hvm::forgetAllWatchLabels();
                }
                safeThis->m_statusLabel->setText(result.message);
                safeThis->refreshAsync();
            },
            Qt::QueuedConnection);
    }).detach();
}

/*
 * showHitEvent：取回这条监视的命中事件并显示完整现场。
 *
 * 读事件环是阻塞 IOCTL，所以放到后台线程；结果回到 UI 线程再弹窗。
 * 查询结果是四态的，四态都要弹窗——尤其是"证据丢了"那一态，那正是用户最需要
 * 一句明确解释的时候。
 */
void HvmWatchPanel::showHitEvent()
{
    ksword::hvm::HvmWatchEntry entry;
    if (!selectedWatch(&entry))
    {
        m_statusLabel->setText(
            text(QStringLiteral("请先在表中选择一条监视。")));
        return;
    }
    setBusy(true);
    m_statusLabel->setText(text(QStringLiteral("正在从事件环取回命中现场...")));
    const QString label = ksword::hvm::watchLabel(entry);
    QPointer<HvmWatchPanel> safeThis(this);
    std::thread([safeThis, entry, label]() {
        const ksword::hvm::HvmWatchHitEvent hit =
            ksword::hvm::findWatchHitEvent(entry);
        if (safeThis == nullptr)
        {
            return;
        }
        QMetaObject::invokeMethod(
            safeThis,
            [safeThis, entry, hit, label]() {
                if (safeThis == nullptr)
                {
                    return;
                }
                safeThis->setBusy(false);
                safeThis->m_statusLabel->setText(hit.message);
                ks::ui::showWatchHitEvent(safeThis, entry, hit, label);
            },
            Qt::QueuedConnection);
    }).detach();
}
