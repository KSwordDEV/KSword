#include "KvmMsrPolicyDialog.h"

#include "KvmControl.h"
#include "../Internationalization/LanguageManager.h"

#include <QComboBox>
#include <QFormLayout>
#include <QGridLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QPointer>
#include <QPushButton>
#include <QTableWidget>
#include <QVBoxLayout>

#include <thread>

namespace
{
    // describeAccess：把拦截方向翻译成一句话。
    QString describeAccess(const unsigned long access)
    {
        const bool read =
            (access & KSWORD_ARK_HVM_MSR_ACCESS_READ) != 0;
        const bool write =
            (access & KSWORD_ARK_HVM_MSR_ACCESS_WRITE) != 0;
        if (read && write)
        {
            return ks::i18n::sourceText(QStringLiteral("读+写"));
        }
        return read
            ? ks::i18n::sourceText(QStringLiteral("读"))
            : ks::i18n::sourceText(QStringLiteral("写"));
    }

    // describeAction：把处置动作翻译成一句话。
    QString describeAction(const unsigned long action)
    {
        switch (action)
        {
        case KSWORD_ARK_HVM_MSR_ACTION_LOG:
            return ks::i18n::sourceText(QStringLiteral("记录后放行"));
        case KSWORD_ARK_HVM_MSR_ACTION_DENY:
            return ks::i18n::sourceText(QStringLiteral("拒绝（注入 #GP）"));
        case KSWORD_ARK_HVM_MSR_ACTION_FAKE:
            return ks::i18n::sourceText(QStringLiteral("伪造读值 / 吞掉写"));
        default:
            break;
        }
        return ks::i18n::sourceText(QStringLiteral("未知动作"));
    }

    // parseHex：解析可带 0x 前缀的十六进制输入。
    bool parseHex(const QString& text, unsigned long long* valueOut)
    {
        QString compact = text.trimmed();
        if (compact.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive))
        {
            compact = compact.mid(2);
        }
        if (compact.isEmpty())
        {
            return false;
        }
        bool converted = false;
        const unsigned long long value = compact.toULongLong(&converted, 16);
        if (!converted)
        {
            return false;
        }
        *valueOut = value;
        return true;
    }
}

KvmMsrPolicyDialog::KvmMsrPolicyDialog(QWidget* const parent)
    : QDialog(parent)
{
    setWindowTitle(ks::i18n::sourceText(QStringLiteral("KVM MSR 策略")));
    setObjectName(QStringLiteral("KvmMsrPolicyDialog"));
    buildUi();
    updateEnabledState();
    refreshPolicies();
}

void KvmMsrPolicyDialog::buildUi()
{
    QVBoxLayout* const rootLayout = new QVBoxLayout(this);

    QLabel* const hintLabel = new QLabel(
        ks::i18n::sourceText(QStringLiteral("只有位图覆盖的两段索引可以设策略：0x00000000-0x00001FFF 与 0xC0000000-0xC0001FFF。常驻期间不能改动策略。")),
        this);
    hintLabel->setWordWrap(true);
    rootLayout->addWidget(hintLabel);

    QFormLayout* const formLayout = new QFormLayout();
    m_msrEdit = new QLineEdit(this);
    m_msrEdit->setPlaceholderText(QStringLiteral("0xC0000082"));
    formLayout->addRow(
        ks::i18n::sourceText(QStringLiteral("MSR 索引（十六进制）")),
        m_msrEdit);

    m_accessBox = new QComboBox(this);
    m_accessBox->addItem(
        ks::i18n::sourceText(QStringLiteral("读")),
        static_cast<unsigned int>(KSWORD_ARK_HVM_MSR_ACCESS_READ));
    m_accessBox->addItem(
        ks::i18n::sourceText(QStringLiteral("写")),
        static_cast<unsigned int>(KSWORD_ARK_HVM_MSR_ACCESS_WRITE));
    m_accessBox->addItem(
        ks::i18n::sourceText(QStringLiteral("读+写")),
        static_cast<unsigned int>(
            KSWORD_ARK_HVM_MSR_ACCESS_READ |
            KSWORD_ARK_HVM_MSR_ACCESS_WRITE));
    formLayout->addRow(
        ks::i18n::sourceText(QStringLiteral("拦截方向")),
        m_accessBox);

    m_actionBox = new QComboBox(this);
    m_actionBox->addItem(
        ks::i18n::sourceText(QStringLiteral("记录后放行（仅读）")),
        static_cast<unsigned int>(KSWORD_ARK_HVM_MSR_ACTION_LOG));
    m_actionBox->addItem(
        ks::i18n::sourceText(QStringLiteral("拒绝（注入 #GP）")),
        static_cast<unsigned int>(KSWORD_ARK_HVM_MSR_ACTION_DENY));
    m_actionBox->addItem(
        ks::i18n::sourceText(QStringLiteral("伪造读值 / 吞掉写")),
        static_cast<unsigned int>(KSWORD_ARK_HVM_MSR_ACTION_FAKE));
    formLayout->addRow(
        ks::i18n::sourceText(QStringLiteral("处置动作")),
        m_actionBox);

    m_fakeValueEdit = new QLineEdit(this);
    m_fakeValueEdit->setPlaceholderText(QStringLiteral("0"));
    formLayout->addRow(
        ks::i18n::sourceText(QStringLiteral("伪造值（十六进制）")),
        m_fakeValueEdit);
    rootLayout->addLayout(formLayout);

    m_policyTable = new QTableWidget(0, 6, this);
    m_policyTable->setHorizontalHeaderLabels(QStringList()
        << ks::i18n::sourceText(QStringLiteral("编号"))
        << ks::i18n::sourceText(QStringLiteral("MSR"))
        << ks::i18n::sourceText(QStringLiteral("方向"))
        << ks::i18n::sourceText(QStringLiteral("动作"))
        << ks::i18n::sourceText(QStringLiteral("伪造值"))
        << ks::i18n::sourceText(QStringLiteral("命中次数")));
    m_policyTable->horizontalHeader()->setStretchLastSection(true);
    m_policyTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_policyTable->setSelectionMode(QAbstractItemView::SingleSelection);
    m_policyTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    rootLayout->addWidget(m_policyTable, 1);

    QGridLayout* const buttonLayout = new QGridLayout();
    m_addButton = new QPushButton(
        ks::i18n::sourceText(QStringLiteral("安装策略")), this);
    m_removeButton = new QPushButton(
        ks::i18n::sourceText(QStringLiteral("移除选中")), this);
    m_clearButton = new QPushButton(
        ks::i18n::sourceText(QStringLiteral("全部移除")), this);
    m_refreshButton = new QPushButton(
        ks::i18n::sourceText(QStringLiteral("刷新")), this);
    buttonLayout->addWidget(m_addButton, 0, 0);
    buttonLayout->addWidget(m_removeButton, 0, 1);
    buttonLayout->addWidget(m_clearButton, 0, 2);
    buttonLayout->addWidget(m_refreshButton, 0, 3);
    rootLayout->addLayout(buttonLayout);

    m_statusLabel = new QLabel(QString(), this);
    m_statusLabel->setWordWrap(true);
    rootLayout->addWidget(m_statusLabel);

    connect(m_actionBox, &QComboBox::currentIndexChanged, this, [this](int) {
        updateEnabledState();
    });
    connect(m_addButton, &QPushButton::clicked, this, [this]() {
        startAdd();
    });
    connect(m_removeButton, &QPushButton::clicked, this, [this]() {
        startRemove();
    });
    connect(m_clearButton, &QPushButton::clicked, this, [this]() {
        startClear();
    });
    connect(m_refreshButton, &QPushButton::clicked, this, [this]() {
        refreshPolicies();
    });
    resize(720, 500);
}

void KvmMsrPolicyDialog::updateEnabledState()
{
    const bool writeAllowed = ksword::kvm::isWriteAccessEnabled();
    const QString writeHint = writeAllowed
        ? QString()
        : ks::i18n::sourceText(QStringLiteral(
            "R-1 写权限未开启：在 KVM 按钮右键菜单中开启后才能安装或移除策略"));
    if (m_addButton != nullptr)
    {
        m_addButton->setEnabled(writeAllowed && !m_busy);
        m_addButton->setToolTip(writeHint);
    }
    if (m_removeButton != nullptr)
    {
        m_removeButton->setEnabled(writeAllowed && !m_busy);
        m_removeButton->setToolTip(writeHint);
    }
    if (m_clearButton != nullptr)
    {
        m_clearButton->setEnabled(writeAllowed && !m_busy);
        m_clearButton->setToolTip(writeHint);
    }
    if (m_refreshButton != nullptr)
    {
        m_refreshButton->setEnabled(!m_busy);
    }
    // 伪造值只对 FAKE 动作有意义。
    if (m_fakeValueEdit != nullptr && m_actionBox != nullptr)
    {
        m_fakeValueEdit->setEnabled(
            m_actionBox->currentData().toUInt() ==
                KSWORD_ARK_HVM_MSR_ACTION_FAKE &&
            !m_busy);
    }
}

void KvmMsrPolicyDialog::setBusy(const bool busy)
{
    m_busy = busy;
    updateEnabledState();
}

void KvmMsrPolicyDialog::refreshPolicies()
{
    if (m_busy)
    {
        return;
    }
    setBusy(true);
    QPointer<KvmMsrPolicyDialog> safeThis(this);
    std::thread([safeThis]() {
        const ksword::kvm::KvmMsrPolicyResult result =
            ksword::kvm::listMsrPolicies();
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
                QTableWidget* const table = safeThis->m_policyTable;
                table->setRowCount(result.policies.size());
                for (int row = 0; row < result.policies.size(); ++row)
                {
                    const auto& entry = result.policies.at(row);
                    table->setItem(row, 0, new QTableWidgetItem(
                        QString::number(entry.policyId)));
                    table->setItem(row, 1, new QTableWidgetItem(
                        QStringLiteral("0x%1")
                            .arg(entry.msrIndex, 8, 16, QLatin1Char('0'))));
                    table->setItem(row, 2, new QTableWidgetItem(
                        describeAccess(entry.access)));
                    table->setItem(row, 3, new QTableWidgetItem(
                        describeAction(entry.action)));
                    table->setItem(row, 4, new QTableWidgetItem(
                        QStringLiteral("0x%1")
                            .arg(entry.fakeValue, 0, 16)));
                    table->setItem(row, 5, new QTableWidgetItem(
                        QString::number(entry.hitCount)));
                }
                safeThis->m_statusLabel->setText(
                    ks::i18n::sourceText(QStringLiteral("已安装 %1 条策略。"))
                        .arg(result.policyCount));
            },
            Qt::QueuedConnection);
    }).detach();
}

void KvmMsrPolicyDialog::startAdd()
{
    unsigned long long msrIndex = 0;
    if (!parseHex(m_msrEdit->text(), &msrIndex) ||
        msrIndex > 0xFFFFFFFFull)
    {
        m_statusLabel->setText(ks::i18n::sourceText(
            QStringLiteral("MSR 索引不是合法的三十二位十六进制数。")));
        return;
    }
    unsigned long long fakeValue = 0;
    const unsigned long action = m_actionBox->currentData().toUInt();
    if (action == KSWORD_ARK_HVM_MSR_ACTION_FAKE &&
        !m_fakeValueEdit->text().trimmed().isEmpty() &&
        !parseHex(m_fakeValueEdit->text(), &fakeValue))
    {
        m_statusLabel->setText(ks::i18n::sourceText(
            QStringLiteral("伪造值不是合法的十六进制数。")));
        return;
    }
    const unsigned long access = m_accessBox->currentData().toUInt();

    setBusy(true);
    m_statusLabel->setText(
        ks::i18n::sourceText(QStringLiteral("正在安装策略...")));
    QPointer<KvmMsrPolicyDialog> safeThis(this);
    std::thread([safeThis, msrIndex, access, action, fakeValue]() {
        const ksword::kvm::KvmMsrPolicyResult result =
            ksword::kvm::addMsrPolicy(
                static_cast<unsigned long>(msrIndex),
                access,
                action,
                fakeValue);
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
                safeThis->m_statusLabel->setText(result.ok
                    ? ks::i18n::sourceText(
                        QStringLiteral("已安装策略，编号 %1。"))
                        .arg(result.policyId)
                    : result.message);
                safeThis->refreshPolicies();
            },
            Qt::QueuedConnection);
    }).detach();
}

void KvmMsrPolicyDialog::startRemove()
{
    const int row = m_policyTable->currentRow();
    if (row < 0 || m_policyTable->item(row, 0) == nullptr)
    {
        m_statusLabel->setText(
            ks::i18n::sourceText(QStringLiteral("请先在表中选择一条策略。")));
        return;
    }
    const unsigned long policyId =
        m_policyTable->item(row, 0)->text().toULong();

    setBusy(true);
    m_statusLabel->setText(
        ks::i18n::sourceText(QStringLiteral("正在移除策略...")));
    QPointer<KvmMsrPolicyDialog> safeThis(this);
    std::thread([safeThis, policyId]() {
        const ksword::kvm::KvmMsrPolicyResult result =
            ksword::kvm::removeMsrPolicy(policyId);
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
                safeThis->refreshPolicies();
            },
            Qt::QueuedConnection);
    }).detach();
}

void KvmMsrPolicyDialog::startClear()
{
    setBusy(true);
    m_statusLabel->setText(
        ks::i18n::sourceText(QStringLiteral("正在移除全部策略...")));
    QPointer<KvmMsrPolicyDialog> safeThis(this);
    std::thread([safeThis]() {
        const ksword::kvm::KvmMsrPolicyResult result =
            ksword::kvm::clearMsrPolicies();
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
                safeThis->refreshPolicies();
            },
            Qt::QueuedConnection);
    }).detach();
}
