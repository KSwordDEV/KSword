#include "KvmEventDialog.h"

#include "KvmControl.h"
#include "../Internationalization/LanguageManager.h"

#include <QCheckBox>
#include <QGridLayout>
#include <QHeaderView>
#include <QLabel>
#include <QPointer>
#include <QPushButton>
#include <QTableWidget>
#include <QTimer>
#include <QVBoxLayout>

#include <thread>

namespace
{
    // 轮询间隔：足够跟上人眼，又不至于把驱动侧状态锁打满。
    constexpr int kPollIntervalMs = 500;
    // 表格行数上限：长时间观察时裁掉最旧的行。
    constexpr int kMaxTableRows = 2000;

    // describeEventType：把事件类型翻译成一句话。
    QString describeEventType(const unsigned long type)
    {
        switch (type)
        {
        case KSWORD_ARK_HVM_EVENT_TYPE_VMEXIT:
            return ks::i18n::sourceText(QStringLiteral("VM-exit"));
        case KSWORD_ARK_HVM_EVENT_TYPE_EPT_VIOLATION:
            return ks::i18n::sourceText(QStringLiteral("EPT 违例"));
        case KSWORD_ARK_HVM_EVENT_TYPE_NESTED_VMX:
            return ks::i18n::sourceText(QStringLiteral("嵌套 VMX"));
        case KSWORD_ARK_HVM_EVENT_TYPE_FATAL_EXIT:
            return ks::i18n::sourceText(QStringLiteral("致命退出"));
        case KSWORD_ARK_HVM_EVENT_TYPE_LIFECYCLE:
            return ks::i18n::sourceText(QStringLiteral("生命周期"));
        default:
            break;
        }
        return ks::i18n::sourceText(QStringLiteral("未知类型"));
    }

    // describeAccess：把 EPT 访问类型翻译成 RWX 简写。
    QString describeAccess(const unsigned long access)
    {
        QString text;
        if ((access & KSWORD_ARK_HVM_EPT_ACCESS_READ) != 0)
        {
            text += QLatin1Char('R');
        }
        if ((access & KSWORD_ARK_HVM_EPT_ACCESS_WRITE) != 0)
        {
            text += QLatin1Char('W');
        }
        if ((access & KSWORD_ARK_HVM_EPT_ACCESS_EXECUTE) != 0)
        {
            text += QLatin1Char('X');
        }
        return text;
    }
}

KvmEventDialog::KvmEventDialog(QWidget* const parent)
    : QDialog(parent)
{
    setWindowTitle(ks::i18n::sourceText(QStringLiteral("KVM 事件流")));
    setObjectName(QStringLiteral("KvmEventDialog"));
    buildUi();
    // 打开时立刻取一次，不必等第一个轮询周期。
    poll();
}

void KvmEventDialog::buildUi()
{
    QVBoxLayout* const rootLayout = new QVBoxLayout(this);

    QLabel* const hintLabel = new QLabel(
        ks::i18n::sourceText(QStringLiteral("事件环是有界的：丢弃计数非零说明消费跟不上产生速度，中间有缺口。")),
        this);
    hintLabel->setWordWrap(true);
    rootLayout->addWidget(hintLabel);

    m_eventTable = new QTableWidget(0, 8, this);
    m_eventTable->setHorizontalHeaderLabels(QStringList()
        << ks::i18n::sourceText(QStringLiteral("序号"))
        << ks::i18n::sourceText(QStringLiteral("类型"))
        << ks::i18n::sourceText(QStringLiteral("退出原因"))
        << ks::i18n::sourceText(QStringLiteral("访问"))
        << ks::i18n::sourceText(QStringLiteral("物理地址"))
        << ks::i18n::sourceText(QStringLiteral("Guest RIP"))
        << ks::i18n::sourceText(QStringLiteral("规则/视图"))
        << ks::i18n::sourceText(QStringLiteral("处理器")));
    m_eventTable->horizontalHeader()->setStretchLastSection(true);
    m_eventTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_eventTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    rootLayout->addWidget(m_eventTable, 1);

    QGridLayout* const buttonLayout = new QGridLayout();
    m_followCheck = new QCheckBox(
        ks::i18n::sourceText(QStringLiteral("自动滚动到最新")), this);
    m_followCheck->setChecked(true);
    m_pauseButton = new QPushButton(
        ks::i18n::sourceText(QStringLiteral("暂停")), this);
    m_clearButton = new QPushButton(
        ks::i18n::sourceText(QStringLiteral("清空")), this);
    buttonLayout->addWidget(m_followCheck, 0, 0);
    buttonLayout->addWidget(m_pauseButton, 0, 1);
    buttonLayout->addWidget(m_clearButton, 0, 2);
    rootLayout->addLayout(buttonLayout);

    m_statusLabel = new QLabel(QString(), this);
    m_statusLabel->setWordWrap(true);
    rootLayout->addWidget(m_statusLabel);

    connect(m_pauseButton, &QPushButton::clicked, this, [this]() {
        m_paused = !m_paused;
        m_pauseButton->setText(m_paused
            ? ks::i18n::sourceText(QStringLiteral("继续"))
            : ks::i18n::sourceText(QStringLiteral("暂停")));
    });
    connect(m_clearButton, &QPushButton::clicked, this, [this]() {
        // 只清界面，不清驱动侧环：环里的历史对别的消费者仍然有意义。
        m_eventTable->setRowCount(0);
        m_droppedTotal = 0;
    });

    m_pollTimer = new QTimer(this);
    m_pollTimer->setInterval(kPollIntervalMs);
    connect(m_pollTimer, &QTimer::timeout, this, [this]() {
        poll();
    });
    m_pollTimer->start();
    resize(900, 560);
}

void KvmEventDialog::trimRows()
{
    // 从头删而不是重建：保留用户当前的选中与滚动位置。
    while (m_eventTable->rowCount() > kMaxTableRows)
    {
        m_eventTable->removeRow(0);
    }
}

void KvmEventDialog::poll()
{
    // 暂停时不发 IOCTL，也不推进游标——继续后能接着看未读的事件。
    if (m_paused || m_pollInFlight)
    {
        return;
    }
    m_pollInFlight = true;
    QPointer<KvmEventDialog> safeThis(this);
    const unsigned long long afterSequence = m_afterSequence;
    std::thread([safeThis, afterSequence]() {
        const ksword::kvm::KvmEventResult result =
            ksword::kvm::readEvents(afterSequence, false);
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
                safeThis->m_pollInFlight = false;
                if (!result.ok)
                {
                    safeThis->m_statusLabel->setText(result.message);
                    return;
                }
                QTableWidget* const table = safeThis->m_eventTable;
                for (const auto& entry : result.events)
                {
                    const int row = table->rowCount();
                    table->insertRow(row);
                    table->setItem(row, 0, new QTableWidgetItem(
                        QString::number(entry.sequence)));
                    table->setItem(row, 1, new QTableWidgetItem(
                        describeEventType(entry.type)));
                    table->setItem(row, 2, new QTableWidgetItem(
                        QString::number(entry.exitReason)));
                    table->setItem(row, 3, new QTableWidgetItem(
                        describeAccess(entry.access)));
                    table->setItem(row, 4, new QTableWidgetItem(
                        QStringLiteral("0x%1")
                            .arg(entry.guestPhysicalAddress, 0, 16)));
                    table->setItem(row, 5, new QTableWidgetItem(
                        QStringLiteral("0x%1")
                            .arg(entry.guestRip, 0, 16)));
                    table->setItem(row, 6, new QTableWidgetItem(
                        entry.ruleId != 0
                            ? QString::number(entry.ruleId)
                            : QString()));
                    table->setItem(row, 7, new QTableWidgetItem(
                        QStringLiteral("%1:%2")
                            .arg(entry.processorGroup)
                            .arg(entry.processorNumber)));
                    // 游标只向前推进，重复读取不会重复上屏。
                    if (entry.sequence >= safeThis->m_afterSequence)
                    {
                        safeThis->m_afterSequence = entry.sequence;
                    }
                }
                safeThis->m_droppedTotal += result.droppedRows;
                safeThis->trimRows();
                if (safeThis->m_followCheck->isChecked() &&
                    table->rowCount() > 0)
                {
                    table->scrollToBottom();
                }
                safeThis->m_statusLabel->setText(
                    ks::i18n::sourceText(QStringLiteral("已显示 %1 行，环内待取 %2 行，累计丢弃 %3 行。"))
                        .arg(table->rowCount())
                        .arg(result.availableRows)
                        .arg(safeThis->m_droppedTotal));
            },
            Qt::QueuedConnection);
    }).detach();
}
