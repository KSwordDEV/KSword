#include "HvmWatchDialog.h"

#include "HvmControl.h"
#include "../Internationalization/LanguageManager.h"
#include "../theme.h"
#include "../../../shared/evidence/MemoryAddressInput.h"

#include <QApplication>
#include <QCheckBox>
#include <QComboBox>
#include <QDialogButtonBox>
#include "./SecondaryPageLayout.h"
#include <QFormLayout>
#include <QGridLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QMetaObject>
#include <QPointer>
#include <QPushButton>
#include <QVBoxLayout>

#include <thread>

namespace
{
    QString text(const QString& source)
    {
        return ks::i18n::sourceText(source);
    }

    /* 解析可带 0x 前缀的十六进制。 */
    bool parseHex(const QString& input, unsigned long long* valueOut)
    {
        const QByteArray compact = input.trimmed().toLatin1();
        std::uint64_t value = 0;
        if (!Ksword::Evidence::ParseHexAddress(
                std::string_view(compact.constData(),
                    static_cast<std::size_t>(compact.size())), value))
        {
            return false;
        }
        *valueOut = value;
        return true;
    }
}

HvmWatchAddDialog::HvmWatchAddDialog(QWidget* const parent)
    : QDialog(parent)
{
    setWindowTitle(text(QStringLiteral("添加内存监视")));
    setObjectName(QStringLiteral("HvmWatchAddDialog"));
    ks::ui::StyleSecondaryWindow(this);
    auto* const rootLayout = new QVBoxLayout(this);
    ks::ui::StyleSecondaryContentLayout(rootLayout);

    m_targetLabel = new QLabel(this);
    m_targetLabel->setWordWrap(true);
    m_targetLabel->setVisible(false);
    m_targetLabel->setStyleSheet(QStringLiteral("font-weight:600;"));
    rootLayout->addWidget(m_targetLabel);

    auto* const form = new QFormLayout();
    m_addressKind = new QComboBox(this);
    m_addressKind->addItem(text(QStringLiteral("内核虚拟地址")), true);
    m_addressKind->addItem(text(QStringLiteral("物理地址")), false);
    form->addRow(text(QStringLiteral("地址类型")), m_addressKind);

    m_address = new QLineEdit(this);
    m_address->setPlaceholderText(QStringLiteral("FFFFF80112345678"));
    form->addRow(text(QStringLiteral("地址（十六进制）")), m_address);

    m_length = new QLineEdit(this);
    m_length->setPlaceholderText(QStringLiteral("8"));
    m_length->setToolTip(text(QStringLiteral("你真正关心的字节数。它不改变硬件监视的范围（那永远是整页），只决定命中后能不能判断这次访问落在你关心的那几个字节上。留空表示整页。")));
    form->addRow(text(QStringLiteral("关心的长度（十进制字节）")), m_length);
    ks::ui::StyleSecondaryForm(form, 186);
    rootLayout->addLayout(form);

    auto* const accessOptions = new QWidget(this);
    auto* const accessRow = new QGridLayout(accessOptions);
    accessRow->setContentsMargins(0, 0, 0, 0);
    accessRow->setHorizontalSpacing(12);
    m_read = new QCheckBox(text(QStringLiteral("读")), this);
    m_write = new QCheckBox(text(QStringLiteral("写")), this);
    m_execute = new QCheckBox(text(QStringLiteral("执行")), this);
    m_write->setChecked(true);
    accessRow->addWidget(m_read, 0, 0);
    accessRow->addWidget(m_write, 0, 1);
    accessRow->addWidget(m_execute, 0, 2);
    accessRow->setColumnStretch(3, 1);
    form->addRow(text(QStringLiteral("监视的访问类型")), accessOptions);

    rootLayout->addWidget(new QLabel(
        text(QStringLiteral("模式：首次访问（当前唯一支持）")), this));

    m_granularity = new QLabel(this);
    m_granularity->setWordWrap(true);
    m_granularity->setStyleSheet(
        QStringLiteral("color:%1;").arg(KswordTheme::TextSecondaryHex()));
    rootLayout->addWidget(m_granularity);

    auto* const buttons = new QDialogButtonBox(
        QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
    buttons->button(QDialogButtonBox::Ok)->setText(text(QStringLiteral("武装")));
    ks::ui::StyleSecondaryButtonBox(buttons);
    rootLayout->addWidget(buttons);
    connect(buttons, &QDialogButtonBox::accepted, this, &HvmWatchAddDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
    connect(m_length, &QLineEdit::textChanged, this, [this](const QString&) {
        updateGranularity();
    });
    connect(m_read, &QCheckBox::toggled, this, [this](bool) {
        updateGranularity();
    });
    updateGranularity();
    resize(560, 360);
}

void HvmWatchAddDialog::prefill(const ks::ui::HvmWatchRequest& request)
{
    m_addressKind->setCurrentIndex(request.virtualAddress ? 0 : 1);
    m_address->setText(QStringLiteral("%1")
        .arg(request.address, 16, 16, QLatin1Char('0')).toUpper());
    if (request.length != 0)
    {
        m_length->setText(QString::number(request.length));
    }
    m_read->setChecked(
        (request.access & KSWORD_ARK_HVM_EPT_ACCESS_READ) != 0UL);
    m_write->setChecked(
        (request.access & KSWORD_ARK_HVM_EPT_ACCESS_WRITE) != 0UL);
    m_execute->setChecked(
        (request.access & KSWORD_ARK_HVM_EPT_ACCESS_EXECUTE) != 0UL);
    if (!request.label.isEmpty())
    {
        m_targetLabel->setText(
            text(QStringLiteral("正在监视：%1")).arg(request.label));
        m_targetLabel->setVisible(true);
        /*
         * 地址栏只读。
         *
         * 调用方已经把"这一项在哪儿"算好了，而顶上那行描述说的正是那个目标。
         * 放开让用户在这里改地址，屏幕上的描述就会与实际监视的东西对不上 ——
         * 之后每一条证据都挂在一句错误的标题下面。要监视别的地址，从内存监视
         * 页手工添加。
         */
        m_address->setReadOnly(true);
        m_addressKind->setEnabled(false);
    }
    updateGranularity();
}

void HvmWatchAddDialog::updateGranularity()
{
    unsigned long long length = 0;
    if (!parseLength(&length))
    {
        m_granularity->setText(text(QStringLiteral(
            "关心的长度必须是十进制无符号整数，或留空表示整页。")));
        return;
    }
    const unsigned long long requested = length != 0ULL ? length : 4096ULL;
    QString note = text(QStringLiteral("EPT 的监视单位是页：你请求 %1 字节，实际装到硬件上的是它所在的整个 4096 字节页。命中后如果 CPU 报告了有效的客户线性地址，界面会另外告诉你这次访问是否落在你请求的那一段里。"))
        .arg(requested);
    if (m_read->isChecked())
    {
        // 这句必须在勾"读"的时候就出现，而不是等安装完才在表里被发现：
        // 用户是在这一刻决定要不要接受"连写也会被监视"的。
        note += QLatin1Char('\n');
        note += text(QStringLiteral("已勾选“读”：EPT 不允许可写而不可读，所以实际生效的监视一定同时包含写；处理器不支持仅执行叶项时还会连带包含执行。表格里的“实际访问”一栏显示归一化后的结果。"));
    }
    m_granularity->setText(note);
}

bool HvmWatchAddDialog::parseLength(unsigned long long* const valueOut) const
{
    const QString input = m_length->text().trimmed();
    if (input.isEmpty())
    {
        *valueOut = 0;
        return true;
    }
    for (const QChar character : input)
    {
        if (character < QLatin1Char('0') || character > QLatin1Char('9'))
        {
            return false;
        }
    }
    bool converted = false;
    const unsigned long long length = input.toULongLong(&converted, 10);
    if (!converted)
    {
        return false;
    }
    *valueOut = length;
    return true;
}

void HvmWatchAddDialog::accept()
{
    unsigned long long length = 0;
    if (!parseLength(&length))
    {
        QMessageBox::warning(this, text(QStringLiteral("添加内存监视")),
            text(QStringLiteral("关心的长度必须是十进制无符号整数，或留空表示整页。")));
        m_length->setFocus();
        return;
    }
    QDialog::accept();
}

ksword::hvm::HvmWatchTarget HvmWatchAddDialog::target() const
{
    ksword::hvm::HvmWatchTarget result;
    result.virtualAddress = m_addressKind->currentData().toBool();
    unsigned long long address = 0;
    if (parseHex(m_address->text(), &address))
    {
        result.address = address;
    }
    if (!parseLength(&result.length))
    {
        // 即使调用方未通过 accept，也不能把非法输入变成整页监视；access=0 拒绝安装。
        return result;
    }
    result.access =
        (m_read->isChecked() ? KSWORD_ARK_HVM_EPT_ACCESS_READ : 0UL) |
        (m_write->isChecked() ? KSWORD_ARK_HVM_EPT_ACCESS_WRITE : 0UL) |
        (m_execute->isChecked() ? KSWORD_ARK_HVM_EPT_ACCESS_EXECUTE : 0UL);
    return result;
}

bool HvmWatchAddDialog::addressValid() const
{
    unsigned long long address = 0;
    return parseHex(m_address->text(), &address) && address != 0;
}

namespace ks::ui
{
    void openHvmWatchOnPte(
        QWidget* const parent,
        const quint64 kernelAddress,
        const QString& label)
    {
        const QString title =
            text(QStringLiteral("监视页表项"));
        if (kernelAddress == 0ULL)
        {
            return;
        }
        /*
         * 走驱动的页表游走后端，不是 HVM 的翻译。
         *
         * 两者回答的东西不一样：HVM 那条只给最终物理地址，而这里要的是**表项
         * 自己住在哪**。只有页表游走后端逐级把表项地址算了出来（它就是按那些
         * 地址把表项读出来的），这个功能拿不到别的来源。
         */
        const ksword::ark::DriverClient client;
        const ksword::ark::VirtualAddressTranslateResult walk =
            client.translateVirtualAddress(0U, kernelAddress);
        if (!walk.io.ok)
        {
            QMessageBox::warning(
                parent,
                title,
                text(QStringLiteral("走不通页表，取不到这个地址的页表项：%1"))
                    .arg(QString::fromStdString(walk.io.message)));
            return;
        }
        /*
         * 大页上根本没有 PTE 这一级。
         *
         * 落在 2 MiB 或 1 GiB 映射上时，映射到此为止由 PDE 或 PDPTE 决定。
         * **不**退回去监视上一级：那是另一个目标，覆盖范围差 512 倍，监视它
         * 然后说成"盯住了这个地址的页表项"是一句假话。直接说清楚。
         */
        if (walk.largePageType != KSWORD_ARK_PAGE_TABLE_LARGE_PAGE_NONE)
        {
            QMessageBox::information(
                parent,
                title,
                text(QStringLiteral("这个地址落在%1大页映射上，映射到 %2 那一级就结束了，没有 PTE 这一项可以监视。\n\n上一级表项覆盖的范围比一页大 512 倍，把它当成「这个地址的页表项」来监视会得到一个范围完全不同的结论，所以这里不替你那么做。"))
                    .arg(walk.largePageType ==
                            KSWORD_ARK_PAGE_TABLE_LARGE_PAGE_1GB
                        ? QStringLiteral("1 GiB")
                        : QStringLiteral("2 MiB"))
                    .arg(walk.largePageType ==
                            KSWORD_ARK_PAGE_TABLE_LARGE_PAGE_1GB
                        ? QStringLiteral("PDPTE")
                        : QStringLiteral("PDE")));
            return;
        }
        /*
         * 门禁看 PTE_PRESENT 位，不看 resolved。
         *
         * resolved 还额外要求终端映射有效；而一个 P=0 的 PTE 会让它为假，
         * 那个 PTE 的地址却早就算出来了。"盯着一个当前不存在的 PTE 等它被
         * 填上"恰恰是最该做的一条监视，用 resolved 当门会把它白白挡掉。
         *
         * 这个标志的名字有误导：它的含义是"这一级走到了、地址已填"，不是
         * "P 位为 1"。当门用对，当"存在"用错。
         */
        if ((walk.fieldFlags & KSWORD_ARK_MEMORY_FIELD_PTE_PRESENT) == 0UL ||
            walk.ptePhysicalAddress == 0ULL)
        {
            QMessageBox::warning(
                parent,
                title,
                text(QStringLiteral("页表游走没有走到 PTE 这一级，取不到表项地址（查询状态 %1）。"))
                    .arg(walk.queryStatus));
            return;
        }
        HvmWatchRequest request;
        // 表项住在物理内存里，按物理地址建监视——它没有稳定的内核虚拟地址。
        request.virtualAddress = false;
        request.address = walk.ptePhysicalAddress;
        /*
         * 一项 8 字节。
         *
         * 这不缩小硬件监视范围（EPT 恒为整页），它决定的是命中之后能不能回答
         * "被改的是不是**你关心的那一项**"——一张页表页上住着 512 个 PTE，
         * 同页任何一项被改都会命中。
         */
        request.length = sizeof(quint64);
        /*
         * 只给写。
         *
         * 读 PTE 的是 CPU 的页表遍历器，频繁到没有归因价值；而勾读还会被架构
         * 归一化连带放大成读写（EPT 不允许可写不可读），等于悄悄换了监视目标。
         */
        request.access = KSWORD_ARK_HVM_EPT_ACCESS_WRITE;
        /*
         * label 里带上原始 VA 与页内偏移。
         *
         * 因为这是物理监视，详情里有两行会退化成无法判断：「落在请求范围内」
         * （拿客户线性地址比物理地址，两个地址空间不可比）与「映射核对」
         * （只对虚拟监视跑）。把 VA 和偏移写进标签，用户还能自己对上——
         * 命中现场的 GLA 低 12 位应当等于这里的偏移。
         */
        request.label = text(QStringLiteral("%1 的页表项（PTE，映射 %2；表项在物理 %3，页内偏移 +0x%4）"))
            .arg(label.isEmpty()
                ? text(QStringLiteral("内核地址 0x%1"))
                    .arg(kernelAddress, 0, 16)
                : label)
            .arg(QStringLiteral("0x%1").arg(kernelAddress, 16, 16,
                QLatin1Char('0')).toUpper())
            .arg(QStringLiteral("0x%1").arg(walk.ptePhysicalAddress, 16, 16,
                QLatin1Char('0')).toUpper())
            .arg(walk.ptePhysicalAddress & 0xFFFULL, 0, 16);
        openHvmWatch(parent, request);
    }

    void openHvmWatch(QWidget* const parent, const HvmWatchRequest& request)
    {
        /*
         * 写权限门在最前面。
         *
         * 它是进程内的开关，不需要发任何 IOCTL 就能判，而且是最常见的拒绝
         * 原因。先问它，用户就不用先填完一张表单再被拒。
         */
        if (!ksword::hvm::isWriteAccessEnabled())
        {
            QMessageBox::warning(
                parent,
                text(QStringLiteral("添加内存监视")),
                text(QStringLiteral("R-1 写权限未开启：请先在标题栏 HVM 按钮的右键菜单里打开它，再安装内存监视。")));
            return;
        }
        HvmWatchAddDialog dialog(parent);
        dialog.prefill(request);
        if (dialog.exec() != QDialog::Accepted)
        {
            return;
        }
        if (!dialog.addressValid())
        {
            QMessageBox::warning(
                parent,
                text(QStringLiteral("添加内存监视")),
                text(QStringLiteral("地址不是合法的非零十六进制数。")));
            return;
        }
        const ksword::hvm::HvmWatchTarget watchTarget = dialog.target();
        if (watchTarget.access == 0UL)
        {
            QMessageBox::warning(
                parent,
                text(QStringLiteral("添加内存监视")),
                text(QStringLiteral("请至少选择一种要监视的访问类型。")));
            return;
        }
        /*
         * 安装是阻塞 IOCTL，必须离开 UI 线程。
         *
         * QPointer 守着 parent：安装期间用户完全可以把那一页关掉，而结果回来
         * 时往一个已经析构的窗口上弹消息框就是一次崩溃。
         */
        QPointer<QWidget> safeParent(parent);
        const QString label = request.label;
        std::thread([safeParent, watchTarget, label]() {
            const ksword::hvm::HvmWatchResult result =
                ksword::hvm::addWatch(watchTarget);
            /*
             * 安装成功就把标签记下来。
             *
             * 标签必须等到这一刻才存得下去：watchId 由驱动分配，在 addWatch
             * 返回之前根本不存在。存的是驱动回填的那一行，因为身份指纹（地址
             * 种类、请求地址、请求长度、实际监视页）要以驱动的读数为准——
             * 用请求值去拼指纹，虚拟地址翻译出来的页就对不上了。
             *
             * 恰好一行才存。ADD 只回填它自己那一条（整表快照是 WATCH_QUERY 的
             * 事），所以行数不是 1 就说明这次回填不是我们以为的那个形状——
             * 那时宁可让"目标"列显示地址，也不能把一句描述挂到一条不确定是
             * 哪个目标的记录上。
             */
            if (result.ok && result.watches.size() == 1)
            {
                ksword::hvm::rememberWatchLabel(result.watches.first(), label);
            }
            QMetaObject::invokeMethod(
                qApp,
                [safeParent, result, label]() {
                    const QString title =
                        text(QStringLiteral("添加内存监视"));
                    // 成功时把"接下来会发生什么"说清楚：这一条不会立刻生效，
                    // 而用户此刻最可能的下一个动作正是去启动常驻。
                    const QString body = result.ok
                        ? text(QStringLiteral("已为 %1 安装内存监视。\n\n监视在启动常驻之后才开始生效；命中一次后会自动解除，届时可在“虚拟化 → 内存监视”页查看现场并重新武装。"))
                            .arg(label.isEmpty()
                                ? text(QStringLiteral("该目标"))
                                : label)
                        : result.message;
                    if (safeParent != nullptr)
                    {
                        result.ok
                            ? QMessageBox::information(safeParent, title, body)
                            : QMessageBox::warning(safeParent, title, body);
                    }
                },
                Qt::QueuedConnection);
        }).detach();
    }
}
