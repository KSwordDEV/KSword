#include "HvmProcessDialog.h"
#include "./SecondaryPageLayout.h"
#include "./ToolbarMetrics.h"
#include "./TableInteractionSupport.h"
#include "./VisibleTableWidget.h"

#include "HvmControl.h"
#include "../../../shared/evidence/MemoryAddressInput.h"
#include "../Framework/DestructiveActionConfirmation.h"
#include "../Internationalization/LanguageManager.h"

#include <QDir>
#include <QFileDialog>
#include <QFormLayout>
#include <QGridLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QPointer>
#include <QPushButton>
#include <QTableWidget>
#include <QTabWidget>
#include <QVBoxLayout>
#include <QVariant>

#include <thread>

namespace
{
    // describeDisposition：把处置类型翻译成一句话。
    QString describeDisposition(const unsigned long disposition)
    {
        switch (disposition)
        {
        case KSWORD_ARK_HVM_PROCESS_OP_FREEZE:
            return ks::i18n::sourceText(QStringLiteral("冻结（注入 #PF，可逆）"));
        case KSWORD_ARK_HVM_PROCESS_OP_TERMINATE:
            return ks::i18n::sourceText(QStringLiteral("结束（注入 #UD，不可逆）"));
        case KSWORD_ARK_HVM_PROCESS_DISPOSITION_RELEASED:
            // 这一态只会出现在常驻期间被撤销的记录上：记录和层次都还在，
            // 但不再有人会切进去。不把它显示出来，用户会以为撤销没生效。
            return ks::i18n::sourceText(QStringLiteral("已解除（层次待回收）"));
        default:
            break;
        }
        return ks::i18n::sourceText(QStringLiteral("未知处置"));
    }

    // describeFiller：空隙原本的填充字节。0xCC 与 0x90 是编译器在函数之间放的
    // 对齐填充，0x00 多半是节尾或未初始化区域——出问题时"用的是哪一种"决定了
    // 该怀疑什么，所以它是表里一列而不是只写进日志。
    QString describeFiller(const unsigned long filler)
    {
        return QStringLiteral("0x%1")
            .arg(filler & 0xFFu, 2, 16, QLatin1Char('0')).toUpper();
    }

    // parseProcessId：十进制 PID。空串和非法输入一律拒绝，不替用户猜 0。
    bool parseProcessId(const QString& text, unsigned long* valueOut)
    {
        bool converted = false;
        const unsigned long value = text.trimmed().toULong(&converted, 10);
        if (!converted)
        {
            return false;
        }
        *valueOut = value;
        return true;
    }

    // parseOptionalHex：可带 0x 前缀的十六进制。空串是合法的，代表"交给下游
    // 去定"（处置的入口页、注入的就地解析 LoadLibraryW），此时回填 0。
    bool parseOptionalHex(const QString& text, unsigned long long* valueOut)
    {
        const QByteArray compact = text.trimmed().toLatin1();
        if (compact.isEmpty())
        {
            *valueOut = 0;
            return true;
        }
        std::uint64_t value = 0;
        if (!Ksword::Evidence::ParseHexAddress(
                std::string_view(compact.constData(), static_cast<std::size_t>(compact.size())), value))
        {
            return false;
        }
        *valueOut = value;
        return true;
    }

    QString hex64(const unsigned long long value)
    {
        return QStringLiteral("0x%1").arg(value, 16, 16, QLatin1Char('0')).toUpper();
    }
}

HvmProcessDialog::HvmProcessDialog(QWidget* const parent)
    : QDialog(parent)
{
    setWindowTitle(ks::i18n::sourceText(QStringLiteral("HVM R-1 进程处置与注入")));
    setObjectName(QStringLiteral("HvmProcessDialog"));
    buildUi();
    updateEnabledState();
    refreshDispositions();
    refreshInjections();
}

void HvmProcessDialog::buildUi()
{
    ks::ui::StyleSecondaryWindow(this);
    QVBoxLayout* const rootLayout = new QVBoxLayout(this);
    ks::ui::StyleSecondaryContentLayout(rootLayout);

    QLabel* const hintLabel = new QLabel(
        ks::i18n::sourceText(QStringLiteral("这两组操作都要求：先开启 CR3 追踪（靠地址空间认目标）、用 EPTP 切换后端准备资源、并且常驻停着。这不是安全边界：目标只要换掉自己那一页的客户物理页就不在被拒绝的页上了，失败即放行。")),
        this);
    hintLabel->setWordWrap(true);
    rootLayout->addWidget(hintLabel);

    m_tabs = new QTabWidget(this);
    ks::ui::StyleSecondaryTabs(m_tabs);
    m_tabs->addTab(
        buildDispositionPage(),
        ks::i18n::sourceText(QStringLiteral("进程处置")));
    m_tabs->addTab(
        buildInjectionPage(),
        ks::i18n::sourceText(QStringLiteral("DLL 注入")));
    rootLayout->addWidget(m_tabs, 1);

    m_statusLabel = new QLabel(QString(), this);
    m_statusLabel->setWordWrap(true);
    rootLayout->addWidget(m_statusLabel);
    resize(880, 560);
}

QWidget* HvmProcessDialog::buildDispositionPage()
{
    QWidget* const page = new QWidget(this);
    QVBoxLayout* const layout = new QVBoxLayout(page);
    layout->setContentsMargins(0, 8, 0, 0);
    layout->setSpacing(12);

    QFormLayout* const form = new QFormLayout();
    m_dispositionPidEdit = new QLineEdit(page);
    m_dispositionPidEdit->setPlaceholderText(QStringLiteral("1234"));
    form->addRow(
        ks::i18n::sourceText(QStringLiteral("目标 PID（十进制）")),
        m_dispositionPidEdit);
    m_dispositionAddressEdit = new QLineEdit(page);
    m_dispositionAddressEdit->setPlaceholderText(
        ks::i18n::sourceText(QStringLiteral("留空表示由驱动取主映像入口页")));
    m_dispositionAddressEdit->setToolTip(ks::i18n::sourceText(QStringLiteral("要拒绝执行的客户线性地址。入口页对刚起来的进程有效；已经跑进消息循环的进程未必会再执行到它，而没被执行到的拒绝等于什么都没做——那时应当填一个目标线程此刻正在执行的地址。")));
    form->addRow(
        ks::i18n::sourceText(QStringLiteral("客户线性地址（十六进制）")),
        m_dispositionAddressEdit);
    ks::ui::StyleSecondaryForm(form, 210);
    layout->addLayout(form);

    m_dispositionTable = new QTableWidget(0, 7, page);
    m_dispositionTable->setHorizontalHeaderLabels(QStringList()
        << ks::i18n::sourceText(QStringLiteral("PID"))
        << ks::i18n::sourceText(QStringLiteral("处置"))
        << ks::i18n::sourceText(QStringLiteral("页目录基址"))
        << ks::i18n::sourceText(QStringLiteral("客户物理地址"))
        << ks::i18n::sourceText(QStringLiteral("客户线性地址"))
        << ks::i18n::sourceText(QStringLiteral("拦截次数"))
        << ks::i18n::sourceText(QStringLiteral("层次序号")));
    m_dispositionTable->horizontalHeader()->setStretchLastSection(true);
    m_dispositionTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_dispositionTable->setSelectionMode(QAbstractItemView::SingleSelection);
    m_dispositionTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    ks::ui::SetTableActionBarMode(m_dispositionTable, ks::ui::TableActionBarMode::None);
    layout->addWidget(m_dispositionTable, 1);

    auto* const footer = new QWidget(page);
    QGridLayout* const buttons = new QGridLayout(footer);
    buttons->setHorizontalSpacing(8);
    m_freezeButton = new QPushButton(
        ks::i18n::sourceText(QStringLiteral("冻结进程")), page);
    m_freezeButton->setToolTip(ks::i18n::sourceText(QStringLiteral("拒绝目标页执行并注入 #PF。目标线程会在那一页上自旋，拦截次数持续增长正是它还活着的证据。可逆。")));
    m_terminateButton = new QPushButton(
        ks::i18n::sourceText(QStringLiteral("结束进程")), page);
    m_terminateButton->setToolTip(ks::i18n::sourceText(QStringLiteral("拒绝目标页执行并注入 #UD，由来宾自己走进程退出流程。不可逆。")));
    m_releaseDispositionButton = new QPushButton(
        ks::i18n::sourceText(QStringLiteral("撤销选中")), page);
    m_releaseAllDispositionsButton = new QPushButton(
        ks::i18n::sourceText(QStringLiteral("全部撤销")), page);
    m_refreshDispositionsButton = new QPushButton(
        ks::i18n::sourceText(QStringLiteral("刷新")), page);
    buttons->addWidget(m_freezeButton, 0, 0);
    buttons->addWidget(m_terminateButton, 0, 1);
    buttons->addWidget(m_releaseDispositionButton, 0, 2);
    buttons->addWidget(m_releaseAllDispositionsButton, 0, 3);
    buttons->addWidget(m_refreshDispositionsButton, 0, 4);
    for (QPushButton* button : { m_freezeButton, m_terminateButton, m_releaseDispositionButton, m_releaseAllDispositionsButton, m_refreshDispositionsButton })
    {
        ks::ui::NormalizeToolbarControl(button);
    }
    ks::ui::StyleSecondaryFooter(footer);
    layout->addWidget(footer);

    connect(m_freezeButton, &QPushButton::clicked, this, [this]() { startFreeze(); });
    connect(m_terminateButton, &QPushButton::clicked, this, [this]() { startTerminate(); });
    connect(m_releaseDispositionButton, &QPushButton::clicked, this, [this]() {
        startReleaseDisposition();
    });
    connect(m_releaseAllDispositionsButton, &QPushButton::clicked, this, [this]() {
        startReleaseAllDispositions();
    });
    connect(m_refreshDispositionsButton, &QPushButton::clicked, this, [this]() {
        refreshDispositions();
    });
    return page;
}

QWidget* HvmProcessDialog::buildInjectionPage()
{
    QWidget* const page = new QWidget(this);
    QVBoxLayout* const layout = new QVBoxLayout(page);
    layout->setContentsMargins(0, 8, 0, 0);
    layout->setSpacing(12);

    QLabel* const note = new QLabel(
        ks::i18n::sourceText(QStringLiteral("机制是分离视图加线程劫持：目标进程里不会多出线程或内存区域，一个内核 API 都不调。代价是要你指定一页——驱动不猜“哪一页会被执行到”，猜错的表现是载荷装上了却永远不执行，从外面看和成功完全一样。")),
        page);
    note->setWordWrap(true);
    layout->addWidget(note);

    QFormLayout* const form = new QFormLayout();
    m_injectPidEdit = new QLineEdit(page);
    m_injectPidEdit->setPlaceholderText(QStringLiteral("1234"));
    form->addRow(
        ks::i18n::sourceText(QStringLiteral("目标 PID（十进制）")),
        m_injectPidEdit);
    m_injectAddressEdit = new QLineEdit(page);
    m_injectAddressEdit->setPlaceholderText(QStringLiteral("00007FF6C1230000"));
    m_injectAddressEdit->setToolTip(ks::i18n::sourceText(QStringLiteral("要劫持的那一页里的任意客户线性地址，必填。取目标某个线程此刻正在执行的位置，那一页按定义会被执行到。")));
    form->addRow(
        ks::i18n::sourceText(QStringLiteral("被劫持页的线性地址（十六进制）")),
        m_injectAddressEdit);
    m_injectLoadLibraryEdit = new QLineEdit(page);
    m_injectLoadLibraryEdit->setPlaceholderText(
        ks::i18n::sourceText(QStringLiteral("留空表示由本程序就地解析")));
    m_injectLoadLibraryEdit->setToolTip(ks::i18n::sourceText(QStringLiteral("kernel32 的 ASLR 每次启动重定一次而不是每进程一次，所以本进程解析出来的 LoadLibraryW 对目标同样成立。只有目标运行在不同的会话映像布局下才需要自己填。")));
    form->addRow(
        ks::i18n::sourceText(QStringLiteral("LoadLibraryW 地址（十六进制）")),
        m_injectLoadLibraryEdit);

    QWidget* const pathRow = new QWidget(page);
    QGridLayout* const pathLayout = new QGridLayout(pathRow);
    pathLayout->setContentsMargins(0, 0, 0, 0);
    m_injectPathEdit = new QLineEdit(pathRow);
    m_injectPathEdit->setPlaceholderText(QStringLiteral("C:\\path\\to\\payload.dll"));
    m_injectBrowseButton = new QPushButton(
        ks::i18n::sourceText(QStringLiteral("浏览...")), pathRow);
    pathLayout->addWidget(m_injectPathEdit, 0, 0);
    pathLayout->addWidget(m_injectBrowseButton, 0, 1);
    pathLayout->setHorizontalSpacing(8);
    ks::ui::NormalizeToolbarControl(m_injectPathEdit);
    ks::ui::NormalizeToolbarControl(m_injectBrowseButton);
    form->addRow(ks::i18n::sourceText(QStringLiteral("DLL 路径")), pathRow);
    ks::ui::StyleSecondaryForm(form, 230);
    layout->addLayout(form);

    m_injectionTable = new QTableWidget(0, 8, page);
    m_injectionTable->setHorizontalHeaderLabels(QStringList()
        << ks::i18n::sourceText(QStringLiteral("PID"))
        << ks::i18n::sourceText(QStringLiteral("被劫持页"))
        << ks::i18n::sourceText(QStringLiteral("客户物理地址"))
        << ks::i18n::sourceText(QStringLiteral("空隙偏移"))
        << ks::i18n::sourceText(QStringLiteral("空隙字节数"))
        << ks::i18n::sourceText(QStringLiteral("填充字节"))
        << ks::i18n::sourceText(QStringLiteral("执行次数"))
        << ks::i18n::sourceText(QStringLiteral("视图编号")));
    m_injectionTable->horizontalHeader()->setStretchLastSection(true);
    m_injectionTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_injectionTable->setSelectionMode(QAbstractItemView::SingleSelection);
    m_injectionTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    ks::ui::SetTableActionBarMode(m_injectionTable, ks::ui::TableActionBarMode::None);
    layout->addWidget(m_injectionTable, 1);

    auto* const footer = new QWidget(page);
    QGridLayout* const buttons = new QGridLayout(footer);
    buttons->setHorizontalSpacing(8);
    m_injectButton = new QPushButton(
        ks::i18n::sourceText(QStringLiteral("注入 DLL")), page);
    m_releaseInjectionButton = new QPushButton(
        ks::i18n::sourceText(QStringLiteral("撤销选中")), page);
    m_releaseAllInjectionsButton = new QPushButton(
        ks::i18n::sourceText(QStringLiteral("全部撤销")), page);
    m_refreshInjectionsButton = new QPushButton(
        ks::i18n::sourceText(QStringLiteral("刷新")), page);
    buttons->addWidget(m_injectButton, 0, 0);
    buttons->addWidget(m_releaseInjectionButton, 0, 1);
    buttons->addWidget(m_releaseAllInjectionsButton, 0, 2);
    buttons->addWidget(m_refreshInjectionsButton, 0, 3);
    for (QPushButton* button : { m_injectButton, m_releaseInjectionButton, m_releaseAllInjectionsButton, m_refreshInjectionsButton })
    {
        ks::ui::NormalizeToolbarControl(button);
    }
    ks::ui::StyleSecondaryFooter(footer);
    layout->addWidget(footer);

    connect(m_injectBrowseButton, &QPushButton::clicked, this, [this]() {
        const QString chosen = QFileDialog::getOpenFileName(
            this,
            ks::i18n::sourceText(QStringLiteral("选择要注入的 DLL")),
            QString(),
            ks::i18n::sourceText(QStringLiteral("动态链接库 (*.dll)")));
        if (!chosen.isEmpty())
        {
            // 统一成反斜杠：载荷是原样交给目标进程里的 LoadLibraryW 的，
            // 而 QFileDialog 在 Windows 上返回的是正斜杠形式。
            m_injectPathEdit->setText(QDir::toNativeSeparators(chosen));
        }
    });
    connect(m_injectButton, &QPushButton::clicked, this, [this]() { startInject(); });
    connect(m_releaseInjectionButton, &QPushButton::clicked, this, [this]() {
        startReleaseInjection();
    });
    connect(m_releaseAllInjectionsButton, &QPushButton::clicked, this, [this]() {
        startReleaseAllInjections();
    });
    connect(m_refreshInjectionsButton, &QPushButton::clicked, this, [this]() {
        refreshInjections();
    });
    return page;
}

void HvmProcessDialog::updateEnabledState()
{
    const bool writeAllowed = ksword::hvm::isWriteAccessEnabled();
    const QString writeHint = writeAllowed
        ? QString()
        : ks::i18n::sourceText(QStringLiteral(
            "R-1 写权限未开启：在 HVM 按钮右键菜单中开启后才能下达处置或注入"));
    for (QPushButton* const button : {
             m_freezeButton, m_terminateButton,
             m_releaseDispositionButton, m_releaseAllDispositionsButton,
             m_injectButton, m_releaseInjectionButton,
             m_releaseAllInjectionsButton })
    {
        if (button == nullptr)
        {
            continue;
        }
        button->setEnabled(writeAllowed && !m_busy);
        // 写权限门的说明**追加**在按钮自己的说明后面，不是替换。
        //
        // 直接覆盖会把「冻结进程」那几条解释按钮做什么的长说明永久挤掉：
        // 写权限在本进程里可以来回切，而覆盖是单向的，切回来时原文已经没了。
        // 第一次调用把原文存进动态属性，之后每次都以它为底重新拼。
        const QVariant stored = button->property("ks_base_tooltip");
        const QString base = stored.isValid() ? stored.toString() : button->toolTip();
        if (!stored.isValid())
        {
            button->setProperty("ks_base_tooltip", base);
        }
        button->setToolTip(writeAllowed ? base
            : base.isEmpty() ? writeHint : base + QLatin1Char('\n') + writeHint);
    }
    for (QPushButton* const button : {
             m_refreshDispositionsButton, m_refreshInjectionsButton })
    {
        if (button != nullptr)
        {
            button->setEnabled(!m_busy);
        }
    }
    if (m_injectBrowseButton != nullptr)
    {
        m_injectBrowseButton->setEnabled(!m_busy);
    }
}

void HvmProcessDialog::setBusy(const bool busy)
{
    m_busy = busy;
    updateEnabledState();
}

bool HvmProcessDialog::readSelectedProcessId(
    QTableWidget* const table,
    unsigned long* const processIdOut)
{
    if (table == nullptr)
    {
        return false;
    }
    const int row = table->currentRow();
    if (row < 0 || table->item(row, 0) == nullptr)
    {
        return false;
    }
    *processIdOut = table->item(row, 0)->text().toULong();
    return true;
}

void HvmProcessDialog::refreshDispositions()
{
    if (m_busy)
    {
        return;
    }
    setBusy(true);
    QPointer<HvmProcessDialog> safeThis(this);
    std::thread([safeThis]() {
        const ksword::hvm::HvmProcessResult result =
            ksword::hvm::listProcessDispositions();
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
                if (!result.ok)
                {
                    safeThis->m_statusLabel->setText(result.message);
                    return;
                }
                QTableWidget* const table = safeThis->m_dispositionTable;
                table->setRowCount(result.dispositions.size());
                for (int row = 0; row < result.dispositions.size(); ++row)
                {
                    const auto& entry = result.dispositions.at(row);
                    table->setItem(row, 0, new QTableWidgetItem(
                        QString::number(entry.processId)));
                    table->setItem(row, 1, new QTableWidgetItem(
                        describeDisposition(entry.disposition)));
                    table->setItem(row, 2, new QTableWidgetItem(
                        hex64(entry.directoryBase)));
                    table->setItem(row, 3, new QTableWidgetItem(
                        hex64(entry.guestPhysicalAddress)));
                    table->setItem(row, 4, new QTableWidgetItem(
                        hex64(entry.guestLinearAddress)));
                    table->setItem(row, 5, new QTableWidgetItem(
                        QString::number(entry.interceptCount)));
                    table->setItem(row, 6, new QTableWidgetItem(
                        QString::number(entry.hierarchyIndex)));
                }
                safeThis->m_statusLabel->setText(
                    ks::i18n::sourceText(QStringLiteral("已安装 %1 条进程处置。"))
                        .arg(result.rowCount));
            },
            Qt::QueuedConnection);
    }).detach();
}

void HvmProcessDialog::refreshInjections()
{
    if (m_busy)
    {
        return;
    }
    setBusy(true);
    QPointer<HvmProcessDialog> safeThis(this);
    std::thread([safeThis]() {
        const ksword::hvm::HvmInjectResult result = ksword::hvm::listInjections();
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
                if (!result.ok)
                {
                    safeThis->m_statusLabel->setText(result.message);
                    return;
                }
                QTableWidget* const table = safeThis->m_injectionTable;
                table->setRowCount(result.injections.size());
                for (int row = 0; row < result.injections.size(); ++row)
                {
                    const auto& entry = result.injections.at(row);
                    table->setItem(row, 0, new QTableWidgetItem(
                        QString::number(entry.processId)));
                    table->setItem(row, 1, new QTableWidgetItem(
                        hex64(entry.guestLinearAddress)));
                    table->setItem(row, 2, new QTableWidgetItem(
                        hex64(entry.guestPhysicalAddress)));
                    table->setItem(row, 3, new QTableWidgetItem(
                        QStringLiteral("0x%1")
                            .arg(entry.caveOffset, 3, 16, QLatin1Char('0'))));
                    table->setItem(row, 4, new QTableWidgetItem(
                        QString::number(entry.caveBytes)));
                    table->setItem(row, 5, new QTableWidgetItem(
                        describeFiller(entry.caveFiller)));
                    table->setItem(row, 6, new QTableWidgetItem(
                        QString::number(entry.executionCount)));
                    table->setItem(row, 7, new QTableWidgetItem(
                        QString::number(entry.viewId)));
                }
                safeThis->m_statusLabel->setText(
                    ks::i18n::sourceText(QStringLiteral("已安装 %1 条 R-1 注入。"))
                        .arg(result.rowCount));
            },
            Qt::QueuedConnection);
    }).detach();
}

void HvmProcessDialog::startFreeze()
{
    unsigned long processId = 0;
    unsigned long long address = 0;
    if (!parseProcessId(m_dispositionPidEdit->text(), &processId))
    {
        m_statusLabel->setText(ks::i18n::sourceText(
            QStringLiteral("PID 不是合法的十进制数。")));
        return;
    }
    if (!parseOptionalHex(m_dispositionAddressEdit->text(), &address))
    {
        m_statusLabel->setText(ks::i18n::sourceText(
            QStringLiteral("客户线性地址不是合法的十六进制数。")));
        return;
    }
    if (!ks::ui::confirmDestructiveAction(
            this,
            QStringLiteral("HvmProcessFreeze"),
            ks::i18n::sourceText(QStringLiteral("冻结进程")),
            ks::i18n::sourceText(QStringLiteral("PID %1")).arg(processId),
            ks::i18n::sourceText(QStringLiteral("目标线程会在被拒绝的那一页上持续自旋，直到这条处置被撤销。若目标是系统进程或正持有锁，系统可能整体失去响应。"))))
    {
        return;
    }
    setBusy(true);
    m_statusLabel->setText(ks::i18n::sourceText(QStringLiteral("正在下达冻结...")));
    QPointer<HvmProcessDialog> safeThis(this);
    std::thread([safeThis, processId, address]() {
        const ksword::hvm::HvmProcessResult result =
            ksword::hvm::freezeProcess(processId, address);
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
                safeThis->refreshDispositions();
            },
            Qt::QueuedConnection);
    }).detach();
}

void HvmProcessDialog::startTerminate()
{
    unsigned long processId = 0;
    unsigned long long address = 0;
    if (!parseProcessId(m_dispositionPidEdit->text(), &processId))
    {
        m_statusLabel->setText(ks::i18n::sourceText(
            QStringLiteral("PID 不是合法的十进制数。")));
        return;
    }
    if (!parseOptionalHex(m_dispositionAddressEdit->text(), &address))
    {
        m_statusLabel->setText(ks::i18n::sourceText(
            QStringLiteral("客户线性地址不是合法的十六进制数。")));
        return;
    }
    if (!ks::ui::confirmDestructiveAction(
            this,
            QStringLiteral("HvmProcessTerminate"),
            ks::i18n::sourceText(QStringLiteral("结束进程")),
            ks::i18n::sourceText(QStringLiteral("PID %1")).arg(processId),
            ks::i18n::sourceText(QStringLiteral("向目标注入无效指令异常，由来宾自己走进程退出流程。不可逆，目标未保存的数据会丢失；若目标是系统进程，系统可能崩溃。"))))
    {
        return;
    }
    setBusy(true);
    m_statusLabel->setText(ks::i18n::sourceText(QStringLiteral("正在下达结束...")));
    QPointer<HvmProcessDialog> safeThis(this);
    std::thread([safeThis, processId, address]() {
        const ksword::hvm::HvmProcessResult result =
            ksword::hvm::terminateProcess(processId, address);
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
                safeThis->refreshDispositions();
            },
            Qt::QueuedConnection);
    }).detach();
}

void HvmProcessDialog::startReleaseDisposition()
{
    unsigned long processId = 0;
    if (!readSelectedProcessId(m_dispositionTable, &processId))
    {
        m_statusLabel->setText(
            ks::i18n::sourceText(QStringLiteral("请先在表中选择一条处置。")));
        return;
    }
    setBusy(true);
    m_statusLabel->setText(ks::i18n::sourceText(QStringLiteral("正在撤销处置...")));
    QPointer<HvmProcessDialog> safeThis(this);
    std::thread([safeThis, processId]() {
        const ksword::hvm::HvmProcessResult result =
            ksword::hvm::releaseProcessDisposition(processId);
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
                safeThis->refreshDispositions();
            },
            Qt::QueuedConnection);
    }).detach();
}

void HvmProcessDialog::startReleaseAllDispositions()
{
    setBusy(true);
    m_statusLabel->setText(
        ks::i18n::sourceText(QStringLiteral("正在撤销全部处置...")));
    QPointer<HvmProcessDialog> safeThis(this);
    std::thread([safeThis]() {
        const ksword::hvm::HvmProcessResult result =
            ksword::hvm::releaseAllProcessDispositions();
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
                safeThis->refreshDispositions();
            },
            Qt::QueuedConnection);
    }).detach();
}

void HvmProcessDialog::startInject()
{
    unsigned long processId = 0;
    unsigned long long address = 0;
    unsigned long long loadLibrary = 0;
    if (!parseProcessId(m_injectPidEdit->text(), &processId))
    {
        m_statusLabel->setText(ks::i18n::sourceText(
            QStringLiteral("PID 不是合法的十进制数。")));
        return;
    }
    // 这个地址与处置那边不同：必填。留空就意味着由驱动去猜哪一页会被执行到，
    // 而猜错的表现与成功无法区分——所以在这里拒绝，而不是传 0 下去。
    if (!parseOptionalHex(m_injectAddressEdit->text(), &address) || address == 0)
    {
        m_statusLabel->setText(ks::i18n::sourceText(
            QStringLiteral("被劫持页的线性地址必填，且必须是合法的十六进制数。")));
        return;
    }
    if (!parseOptionalHex(m_injectLoadLibraryEdit->text(), &loadLibrary))
    {
        m_statusLabel->setText(ks::i18n::sourceText(
            QStringLiteral("LoadLibraryW 地址不是合法的十六进制数。")));
        return;
    }
    const QString path = m_injectPathEdit->text().trimmed();
    if (path.isEmpty())
    {
        m_statusLabel->setText(
            ks::i18n::sourceText(QStringLiteral("请先选择要注入的 DLL。")));
        return;
    }
    if (!ks::ui::confirmDestructiveAction(
            this,
            QStringLiteral("HvmProcessInject"),
            ks::i18n::sourceText(QStringLiteral("R-1 注入 DLL")),
            ks::i18n::sourceText(QStringLiteral("PID %1")).arg(processId),
            ks::i18n::sourceText(QStringLiteral("将在目标进程的一页可执行内存上建立影子页并劫持其执行流。载荷在目标进程上下文里运行，出错会让目标崩溃；若目标是系统进程，系统可能崩溃。"))))
    {
        return;
    }
    setBusy(true);
    m_statusLabel->setText(ks::i18n::sourceText(QStringLiteral("正在安装注入...")));
    QPointer<HvmProcessDialog> safeThis(this);
    std::thread([safeThis, processId, address, loadLibrary, path]() {
        const ksword::hvm::HvmInjectResult result =
            ksword::hvm::injectDll(processId, address, loadLibrary, path);
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
                safeThis->refreshInjections();
            },
            Qt::QueuedConnection);
    }).detach();
}

void HvmProcessDialog::startReleaseInjection()
{
    unsigned long processId = 0;
    if (!readSelectedProcessId(m_injectionTable, &processId))
    {
        m_statusLabel->setText(
            ks::i18n::sourceText(QStringLiteral("请先在表中选择一条注入。")));
        return;
    }
    setBusy(true);
    m_statusLabel->setText(ks::i18n::sourceText(QStringLiteral("正在撤销注入...")));
    QPointer<HvmProcessDialog> safeThis(this);
    std::thread([safeThis, processId]() {
        const ksword::hvm::HvmInjectResult result =
            ksword::hvm::releaseInjection(processId);
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
                safeThis->refreshInjections();
            },
            Qt::QueuedConnection);
    }).detach();
}

void HvmProcessDialog::startReleaseAllInjections()
{
    setBusy(true);
    m_statusLabel->setText(
        ks::i18n::sourceText(QStringLiteral("正在撤销全部注入...")));
    QPointer<HvmProcessDialog> safeThis(this);
    std::thread([safeThis]() {
        const ksword::hvm::HvmInjectResult result =
            ksword::hvm::releaseAllInjections();
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
                safeThis->refreshInjections();
            },
            Qt::QueuedConnection);
    }).detach();
}
