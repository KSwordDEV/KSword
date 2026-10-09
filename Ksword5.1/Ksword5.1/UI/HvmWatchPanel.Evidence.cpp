// HvmWatchPanel.Evidence：内存监视页「命中之后往哪去」的那一半。
//
// 与 HvmWatchPanel.cpp 的分界不是行数，而是两组动作回答的问题不同：那一份管
// 表格本身（读表、铺表、装/撤/重新武装/清空），这一份管拿到一次命中之后能做
// 什么——看写入者的反汇编、看写入者那段内存、看它所在整页、看被监视的目标、
// 定位模块文件、把 CR3 反查成进程、复制与导出证据。
//
// 这一半有两条贯穿始终的规矩：
//
// - **读的是哪一段必须写在读数里。** 「目标内存」与「写入者内存」是两段完全
//   不同的东西，转储出来长得一模一样；不写清楚，两份读数会被当成同一份。
// - **归不出来与「确实不属于任何模块」要分开。** 后者是一条值得继续追的可疑
//   读数，前者只是这次没问出来。把前者显示成后者，就是把一次失败伪装成结论。

#include "HvmWatchPanel.h"

#include "KernelDisassemblyDialog.h"
#include "HvmControl.h"
#include "HvmWatchEventDialog.h"
#include "../Internationalization/LanguageManager.h"

#include <QApplication>
#include <QByteArray>
#include <QClipboard>
#include <QDateTime>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QLabel>
#include <QMetaObject>
#include <QPointer>
#include "StructuredFieldView.h"
#include <QProcess>
#include <QPushButton>
#include <QStringList>
#include <QTableWidget>
#include <QTextEdit>
#include <QTextStream>

#include <thread>

namespace
{
    // text / hex64：与 HvmWatchPanel.cpp 同一套，两份文件里的读数格式必须一致。
    QString text(const QString& source)
    {
        return ks::i18n::sourceText(source);
    }

    QString hex64(const unsigned long long value)
    {
        return QStringLiteral("0x%1")
            .arg(value, 16, 16, QLatin1Char('0')).toUpper();
    }
}

void HvmWatchPanel::openWriterDisassembly()
{
    ksword::hvm::HvmWatchEntry entry;
    if (!selectedWatch(&entry) ||
        entry.lastHitRip == 0ULL)
    {
        return;
    }
    /*
     * 从命中的 RIP 往前退一点再开始反汇编。
     *
     * RIP 指向的是**尚未完成**的那条指令：EPT violation 发生在导致访问的指令
     * 退休之前。只从 RIP 开始看，用户看到的是那条指令本身，看不到它前面几条
     * 在算什么地址——而"这个写是怎么被算出来的"往往才是要找的东西。
     */
    const unsigned long long start = entry.lastHitRip >= 0x40ULL
        ? entry.lastHitRip - 0x40ULL
        : entry.lastHitRip;
    ks::ui::KernelDisassemblyDialog::openKernelAddress(
        this,
        start,
        text(QStringLiteral("内存监视 #%1 命中的 RIP %2"))
            .arg(entry.watchId)
            .arg(hex64(entry.lastHitRip)),
        0x200U);
}

/*
 * openWriterMemory：按命中 RIP 读一段内存。
 *
 * 它与 openTargetMemory 读的不是同一段：那个读被监视的目标，这个读发起访问的
 * 那段代码。issue 第十节要求 RIP 归不到任何已加载模块时必须提供「打开内存」，
 * 而「查看目标内存」按钮硬绑在监视目标上，任何情况下都不会去读 RIP 那一段。
 */
void HvmWatchPanel::openWriterMemory()
{
    ksword::hvm::HvmWatchEntry entry;
    if (!selectedWatch(&entry) || entry.lastHitRip == 0ULL)
    {
        return;
    }
    const ksword::hvm::HvmMemoryResult result =
        ksword::hvm::readVirtual(0, entry.lastHitRip, 256U);
    if (!result.ok)
    {
        m_statusLabel->setText(
            text(QStringLiteral("读不到写入者所在的内存：%1"))
                .arg(result.message));
        return;
    }
    ks::ui::FieldDocument document;
    // 抬头必须写清读的是写入者而不是目标，否则两段转储在详情框里长得一样。
    document.note(text(QStringLiteral("写入者所在内存（命中 RIP %1 起 %2 字节；这是命中之后的采样）"))
        .arg(hex64(entry.lastHitRip))
        .arg(result.data.size()));

    for (int offset = 0; offset < result.data.size(); offset += 16)
    {
        const QByteArray chunk = result.data.mid(offset, 16);
        document.field(hex64(entry.lastHitRip + static_cast<unsigned long long>(offset)),
            QString::fromLatin1(chunk.toHex(' ')));
    }
    m_detail->setDocument(document);
    m_statusLabel->setText(text(QStringLiteral(
        "已读出写入者所在的内存。这读的是发起访问的那段代码，不是被监视的目标。")));
}

/*
 * openWriterPage：把命中 RIP 所在的整页拿去反汇编。
 *
 * 整页而不是一小段：要判断一段不属于任何已加载模块的代码究竟是什么，看 0x200
 * 字节看不出来——有没有函数序言、是不是一整块被回收的池、页尾是不是全零，
 * 这些都要整页才看得见。
 */
void HvmWatchPanel::openWriterPage()
{
    ksword::hvm::HvmWatchEntry entry;
    if (!selectedWatch(&entry) || entry.lastHitRip == 0ULL)
    {
        return;
    }
    const unsigned long long page = entry.lastHitRip & ~0xFFFULL;
    ks::ui::KernelDisassemblyDialog::openKernelAddress(
        this,
        page,
        text(QStringLiteral("内存监视 #%1 命中 RIP %2 所在的整页 %3"))
            .arg(entry.watchId)
            .arg(hex64(entry.lastHitRip))
            .arg(hex64(page)),
        4096U);
}

void HvmWatchPanel::openTargetMemory()
{
    ksword::hvm::HvmWatchEntry entry;
    if (!selectedWatch(&entry) || entry.physicalPage == 0ULL)
    {
        return;
    }
    /*
     * 优先按虚拟地址读，读不到**真的**退回物理页再读一次。
     *
     * 两者不等价：虚拟地址读的是"这个 VA 现在指向的东西"，物理页读的是"被监视
     * 的那一页"。重映射、解提交、换出之后这两个是不同的页，而用户要看的几乎
     * 总是后者——被监视的那一页一直都在，readPhysical 也一直读得到。
     *
     * 之前这段只写了这条回退的注释，代码却是一次三元选择：虚拟读失败就直接
     * 报"读不到目标内存"返回，从不改用已知的物理页。于是恰好在最需要看一眼
     * 当前内容的场景（VA 已经不指向那一页了）里，一个字都读不出来。
     */
    const bool preferVirtual =
        entry.addressKind == KSWORD_ARK_HVM_WATCH_ADDRESS_VIRTUAL &&
        entry.requestedAddress != 0ULL;
    unsigned long long address = preferVirtual
        ? entry.requestedAddress
        : entry.physicalPage;
    bool byVirtual = preferVirtual;
    ksword::hvm::HvmMemoryResult result = preferVirtual
        ? ksword::hvm::readVirtual(0, address, 256U)
        : ksword::hvm::readPhysical(address, 256U);
    // 虚拟读失败时的退路；记下第一条失败原因，读数里要把两段都摆出来。
    QString virtualFailure;
    if (!result.ok && preferVirtual)
    {
        virtualFailure = result.message;
        byVirtual = false;
        address = entry.physicalPage;
        result = ksword::hvm::readPhysical(address, 256U);
    }
    if (!result.ok)
    {
        m_statusLabel->setText(virtualFailure.isEmpty()
            ? text(QStringLiteral("读不到目标内存：%1")).arg(result.message)
            : text(QStringLiteral("读不到目标内存：按虚拟地址失败（%1），退回被监视的物理页也失败（%2）。"))
                .arg(virtualFailure)
                .arg(result.message));
        return;
    }
    ks::ui::FieldDocument document;
    document.section(QStringLiteral("目标内存（命中之后的采样，不是命中那一刻的值）"));
    document.note((byVirtual
        ? text(QStringLiteral("  按虚拟地址 %1 读 %2 字节"))
            .arg(hex64(address)).arg(result.data.size())
        : text(QStringLiteral("  按被监视的物理页 %1 读 %2 字节"))
            .arg(hex64(address)).arg(result.data.size())));
    if (!virtualFailure.isEmpty())
    {
        // 说清楚读的是哪一个，否则用户会以为看到的是那个虚拟地址上的内容。
        document.field(QStringLiteral(""), QStringLiteral("按虚拟地址 %1 读不到（%2），上面这段是被监视的那一页，不是该虚拟地址当前指向的内容。")
            .arg(hex64(entry.requestedAddress))
            .arg(virtualFailure));
    }

    for (int offset = 0; offset < result.data.size(); offset += 16)
    {
        const QByteArray chunk = result.data.mid(offset, 16);
        document.field(hex64(address + static_cast<unsigned long long>(offset)),
            QString::fromLatin1(chunk.toHex(' ')));
    }
    m_detail->setDocument(document);
    m_statusLabel->setText(text(QStringLiteral(
        "已读出目标内存。这是命中之后的采样：EPT violation 发生在写指令退休之前，所以这里看到的可能已经包含那次写入，也可能还包含之后的更多次修改。")));
}

void HvmWatchPanel::openWriterModule()
{
    ksword::hvm::HvmWatchEntry entry;
    if (!selectedWatch(&entry) || entry.lastHitRip == 0ULL)
    {
        return;
    }
    const ksword::hvm::HvmWatchAttribution attribution =
        ksword::hvm::attributeKernelAddress(entry.lastHitRip);
    // 失败与"确实不在模块里"要分开说：前者是这次没问出来，后者才是结论。
    if (attribution.kind == ksword::hvm::HvmWatchAttributionKind::Failed)
    {
        m_statusLabel->setText(text(QStringLiteral(
            "读不到系统模块表，这次归因没跑起来，所以答不出这个 RIP 属于哪个模块——这不等于它不属于任何模块。")));
        return;
    }
    if (!attribution.resolved || attribution.modulePath.isEmpty())
    {
        m_statusLabel->setText(text(QStringLiteral(
            "这个 RIP 不落在任何已加载内核模块里，没有模块文件可打开。")));
        return;
    }
    /*
     * 内核回报的是 \SystemRoot\ 这类 NT 路径，资源管理器不认。
     *
     * 转换失败时不要退回"就用原串试试"：资源管理器会拿一个不存在的路径开一个
     * 默认目录，看起来像成功了，而用户会以为自己正在看那个模块所在的目录。
     */
    const QString win32Path = ksword::hvm::toWin32ModulePath(attribution.modulePath);
    if (win32Path.isEmpty() || !QFileInfo::exists(win32Path))
    {
        m_statusLabel->setText(
            text(QStringLiteral("模块文件 %1 在磁盘上找不到。"))
                .arg(attribution.modulePath));
        return;
    }
    QProcess::startDetached(
        QStringLiteral("explorer.exe"),
        QStringList() << QStringLiteral("/select,")
                      << QDir::toNativeSeparators(win32Path));
    m_statusLabel->setText(
        text(QStringLiteral("已在资源管理器里定位 %1。")).arg(win32Path));
}

void HvmWatchPanel::resolveHitProcess()
{
    ksword::hvm::HvmWatchEntry entry;
    if (!selectedWatch(&entry) || entry.lastHitCr3 == 0ULL)
    {
        return;
    }
    const quint64 cr3 = entry.lastHitCr3;
    setBusy(true);
    m_statusLabel->setText(text(QStringLiteral(
        "正在按 CR3 逐个进程反查地址空间...")));
    QPointer<HvmWatchPanel> safeThis(this);
    std::thread([safeThis, cr3]() {
        const ksword::hvm::HvmProcessAttribution attribution =
            ksword::hvm::attributeProcessByCr3(cr3);
        if (safeThis == nullptr)
        {
            return;
        }
        QMetaObject::invokeMethod(
            safeThis,
            [safeThis, cr3, attribution]() {
                if (safeThis == nullptr)
                {
                    return;
                }
                safeThis->m_processAttribution.insert(cr3, attribution);
                safeThis->setBusy(false);
                safeThis->m_statusLabel->setText(
                    ksword::hvm::describeProcessAttribution(attribution));
                ksword::hvm::HvmWatchEntry selected;
                if (safeThis->selectedWatch(&selected))
                {
                    safeThis->showDetail(selected);
                }
            },
            Qt::QueuedConnection);
    }).detach();
}

void HvmWatchPanel::exportEvidence()
{
    if (m_table == nullptr || m_table->rowCount() == 0)
    {
        return;
    }
    const QString path = QFileDialog::getSaveFileName(
        this,
        text(QStringLiteral("导出内存监视证据")),
        QStringLiteral("hvm-memory-watch-%1.txt")
            .arg(QDateTime::currentDateTime().toString(
                QStringLiteral("yyyyMMdd-HHmmss"))),
        text(QStringLiteral("文本文件 (*.txt)")));
    if (path.isEmpty())
    {
        return;
    }
    QStringList blocks;
    blocks << text(QStringLiteral("KSword R-1 内存监视证据"));
    blocks << text(QStringLiteral("导出时间：%1"))
        .arg(QDateTime::currentDateTime().toString(Qt::ISODate));
    // 边界写在最前面：这份文件会被单独传阅，而"这不是保护"那句话不能留在
    // 界面上没跟出来。
    blocks << text(QStringLiteral("这是观察与归因记录，不是保护：命中不阻止访问；硬件监视单位是 4 KiB 页而不是请求范围；DMA 改写不经过 CPU 的 EPT；虚拟地址的绑定在武装那一刻定死，之后的重映射不跟踪。"));
    blocks << QString();
    for (int row = 0; row < m_table->rowCount(); ++row)
    {
        QTableWidgetItem* const item = m_table->item(row, WatchColumnId);
        if (item == nullptr)
        {
            continue;
        }
        const QVariant stored = item->data(Qt::UserRole);
        if (!stored.isValid())
        {
            continue;
        }
        // 复用详情框那一份格式：屏幕上看到的和导出的必须是同一份东西，
        // 另拼一份会让两者随时间漂开。
        showDetail(stored.value<ksword::hvm::HvmWatchEntry>());
        blocks << QStringLiteral("================================");
        blocks << m_detail->plainText();
        blocks << QString();
    }
    QFile file(path);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text))
    {
        m_statusLabel->setText(
            text(QStringLiteral("导出失败：无法写入 %1。")).arg(path));
        return;
    }
    // 显式 UTF-8：这份文件里全是中文标签，跟着系统区域走会在别人机器上变成乱码。
    QTextStream stream(&file);
    stream.setEncoding(QStringConverter::Utf8);
    stream << blocks.join(QLatin1Char('\n'));
    file.close();
    m_statusLabel->setText(
        text(QStringLiteral("已导出 %1 条监视的完整证据到 %2。"))
            .arg(m_table->rowCount())
            .arg(path));
    // 导出会把详情框停在最后一条上；把选中那一条重新画回去，免得屏幕上
    // 显示的与选中行对不上。
    ksword::hvm::HvmWatchEntry selected;
    if (selectedWatch(&selected))
    {
        showDetail(selected);
    }
}

void HvmWatchPanel::copyEvidence()
{
    ksword::hvm::HvmWatchEntry entry;
    if (!selectedWatch(&entry))
    {
        return;
    }
    // 直接复制详情框的原文：屏幕上看到的和粘贴出去的必须是同一份东西，
    // 另拼一份格式会让两者随时间漂开。
    showDetail(entry);
    QApplication::clipboard()->setText(m_detail->plainText());
    m_statusLabel->setText(
        text(QStringLiteral("已把这条监视的完整证据复制到剪贴板。")));
}
