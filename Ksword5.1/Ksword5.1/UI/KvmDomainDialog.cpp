#include "KvmDomainDialog.h"

#include "KvmControl.h"
#include "../Internationalization/LanguageManager.h"

#include <QCheckBox>
#include <QFormLayout>
#include <QGridLayout>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPointer>
#include <QPushButton>
#include <QTableWidget>
#include <QVBoxLayout>

#include <thread>

namespace
{
    // parseHex：解析可选带 0x 前缀的十六进制数。
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

KvmDomainDialog::KvmDomainDialog(QWidget* const parent)
    : QDialog(parent)
{
    setWindowTitle(ks::i18n::sourceText(QStringLiteral("KVM EPT 执行域")));
    setObjectName(QStringLiteral("KvmDomainDialog"));
    buildUi();
    updateEnabledState();
    refreshDomains();
}

void KvmDomainDialog::buildUi()
{
    QVBoxLayout* const rootLayout = new QVBoxLayout(this);

    QLabel* const hintLabel = new QLabel(
        ks::i18n::sourceText(QStringLiteral("域发布在 EPTP list 里，guest 用一条 VMFUNC 就能切过去，而 VMFUNC 不做 CPL 检查。所以这里只能给域【拿掉】权限，不能给权限：域建出来时与默认视图完全一致，切进去的线程拿不到它原本没有的访问权。")),
        this);
    hintLabel->setWordWrap(true);
    rootLayout->addWidget(hintLabel);

    QLabel* const armLabel = new QLabel(
        ks::i18n::sourceText(QStringLiteral("建域本身不改变任何行为。要让 VMFUNC 真的能切，还得用带「武装 VMFUNC」的常驻启动。")),
        this);
    armLabel->setWordWrap(true);
    rootLayout->addWidget(armLabel);

    m_domainTable = new QTableWidget(0, 4, this);
    m_domainTable->setHorizontalHeaderLabels(QStringList()
        << ks::i18n::sourceText(QStringLiteral("槽位"))
        << ks::i18n::sourceText(QStringLiteral("状态"))
        << ks::i18n::sourceText(QStringLiteral("已分叉页表"))
        << ks::i18n::sourceText(QStringLiteral("EPT 指针")));
    m_domainTable->horizontalHeader()->setStretchLastSection(true);
    m_domainTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_domainTable->setSelectionMode(QAbstractItemView::SingleSelection);
    m_domainTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    rootLayout->addWidget(m_domainTable, 1);

    QFormLayout* const formLayout = new QFormLayout();
    m_domainEdit = new QLineEdit(this);
    m_domainEdit->setPlaceholderText(QStringLiteral("1"));
    formLayout->addRow(
        ks::i18n::sourceText(QStringLiteral("目标域槽位（十进制，0 号是默认视图）")),
        m_domainEdit);

    m_addressEdit = new QLineEdit(this);
    m_addressEdit->setPlaceholderText(QStringLiteral("0x100000"));
    formLayout->addRow(
        ks::i18n::sourceText(QStringLiteral("物理起始地址（十六进制）")),
        m_addressEdit);

    m_lengthEdit = new QLineEdit(this);
    m_lengthEdit->setPlaceholderText(QStringLiteral("0x200000"));
    formLayout->addRow(
        ks::i18n::sourceText(QStringLiteral("长度（十六进制，按 2MiB 叶项向外取整）")),
        m_lengthEdit);
    rootLayout->addLayout(formLayout);

    QHBoxLayout* const denyLayout = new QHBoxLayout();
    QLabel* const denyLabel = new QLabel(
        ks::i18n::sourceText(QStringLiteral("拿掉的权限")),
        this);
    m_denyReadBox = new QCheckBox(
        ks::i18n::sourceText(QStringLiteral("读")), this);
    m_denyReadBox->setToolTip(ks::i18n::sourceText(QStringLiteral("拿掉读权限需要处理器支持仅执行的 EPT 叶项，否则驱动会拒绝——那样的叶项会让 VM entry 直接失败。")));
    m_denyWriteBox = new QCheckBox(
        ks::i18n::sourceText(QStringLiteral("写")), this);
    m_denyExecuteBox = new QCheckBox(
        ks::i18n::sourceText(QStringLiteral("执行")), this);
    denyLayout->addWidget(denyLabel);
    denyLayout->addWidget(m_denyReadBox);
    denyLayout->addWidget(m_denyWriteBox);
    denyLayout->addWidget(m_denyExecuteBox);
    denyLayout->addStretch(1);
    rootLayout->addLayout(denyLayout);

    QGridLayout* const buttonLayout = new QGridLayout();
    m_createButton = new QPushButton(
        ks::i18n::sourceText(QStringLiteral("新建域")), this);
    m_createButton->setToolTip(ks::i18n::sourceText(QStringLiteral("分叉一份与默认视图完全一致的域。只花一页，因为下层页表全部共享。")));
    m_restrictButton = new QPushButton(
        ks::i18n::sourceText(QStringLiteral("收紧权限")), this);
    m_resetButton = new QPushButton(
        ks::i18n::sourceText(QStringLiteral("清空全部域")), this);
    m_refreshButton = new QPushButton(
        ks::i18n::sourceText(QStringLiteral("刷新")), this);
    buttonLayout->addWidget(m_createButton, 0, 0);
    buttonLayout->addWidget(m_restrictButton, 0, 1);
    buttonLayout->addWidget(m_resetButton, 0, 2);
    buttonLayout->addWidget(m_refreshButton, 0, 3);
    rootLayout->addLayout(buttonLayout);

    m_statusLabel = new QLabel(QString(), this);
    m_statusLabel->setWordWrap(true);
    rootLayout->addWidget(m_statusLabel);

    connect(m_createButton, &QPushButton::clicked, this, [this]() {
        startCreate();
    });
    connect(m_restrictButton, &QPushButton::clicked, this, [this]() {
        startRestrict();
    });
    connect(m_resetButton, &QPushButton::clicked, this, [this]() {
        startReset();
    });
    connect(m_refreshButton, &QPushButton::clicked, this, [this]() {
        refreshDomains();
    });
    // 选中一行就把槽位填进输入框，省得手抄。
    connect(m_domainTable, &QTableWidget::itemSelectionChanged, this, [this]() {
        const auto selected = m_domainTable->selectedItems();
        if (selected.isEmpty())
        {
            return;
        }
        const int row = selected.first()->row();
        QTableWidgetItem* const item = m_domainTable->item(row, 0);
        if (item != nullptr)
        {
            m_domainEdit->setText(item->text());
        }
    });
    resize(720, 540);
}

void KvmDomainDialog::updateEnabledState()
{
    const bool writeAllowed = ksword::kvm::isWriteAccessEnabled();
    const QString writeHint = writeAllowed
        ? QString()
        : ks::i18n::sourceText(QStringLiteral("R-1 写权限未开启：在 KVM 按钮右键菜单中开启后才能建域或收紧权限"));
    if (m_createButton != nullptr)
    {
        m_createButton->setEnabled(writeAllowed && !m_busy);
        if (!writeAllowed)
        {
            m_createButton->setToolTip(writeHint);
        }
    }
    if (m_restrictButton != nullptr)
    {
        m_restrictButton->setEnabled(writeAllowed && !m_busy);
        m_restrictButton->setToolTip(writeHint);
    }
    if (m_resetButton != nullptr)
    {
        m_resetButton->setEnabled(writeAllowed && !m_busy);
        m_resetButton->setToolTip(writeHint);
    }
    if (m_refreshButton != nullptr)
    {
        m_refreshButton->setEnabled(!m_busy);
    }
}

void KvmDomainDialog::setBusy(const bool busy)
{
    m_busy = busy;
    updateEnabledState();
}

void KvmDomainDialog::refreshDomains()
{
    if (m_busy)
    {
        return;
    }
    setBusy(true);
    QPointer<KvmDomainDialog> safeThis(this);
    std::thread([safeThis]() {
        const ksword::kvm::KvmDomainResult result =
            ksword::kvm::listDomains();
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
                QTableWidget* const table = safeThis->m_domainTable;
                table->setRowCount(result.domains.size());
                for (int row = 0; row < result.domains.size(); ++row)
                {
                    const auto& entry = result.domains.at(row);
                    table->setItem(row, 0, new QTableWidgetItem(
                        QString::number(entry.domainIndex)));
                    // 0 号槽位永远是默认视图，标出来免得被当成可收紧的副本。
                    const QString state = entry.domainIndex == 0
                        ? ks::i18n::sourceText(QStringLiteral("默认视图"))
                        : (entry.active
                            ? ks::i18n::sourceText(QStringLiteral("已建立"))
                            : ks::i18n::sourceText(QStringLiteral("空闲")));
                    table->setItem(row, 1, new QTableWidgetItem(state));
                    table->setItem(row, 2, new QTableWidgetItem(
                        QString::number(entry.privateTableCount)));
                    table->setItem(row, 3, new QTableWidgetItem(
                        entry.eptPointer == 0
                            ? QStringLiteral("-")
                            : QStringLiteral("0x%1")
                                .arg(entry.eptPointer, 0, 16)));
                }
                safeThis->m_statusLabel->setText(
                    ks::i18n::sourceText(QStringLiteral("当前有 %1 个域（含默认视图）。"))
                        .arg(result.domainCount));
            },
            Qt::QueuedConnection);
    }).detach();
}

void KvmDomainDialog::startCreate()
{
    if (m_busy)
    {
        return;
    }
    setBusy(true);
    QPointer<KvmDomainDialog> safeThis(this);
    std::thread([safeThis]() {
        const ksword::kvm::KvmDomainResult result =
            ksword::kvm::createDomain();
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
                    ? ks::i18n::sourceText(QStringLiteral("已建立 %1 号域，内容与默认视图一致。"))
                        .arg(result.domainIndex)
                    : result.message);
                safeThis->refreshDomains();
            },
            Qt::QueuedConnection);
    }).detach();
}

void KvmDomainDialog::startRestrict()
{
    if (m_busy)
    {
        return;
    }
    bool converted = false;
    const unsigned long domainIndex =
        m_domainEdit->text().trimmed().toULong(&converted, 10);
    if (!converted)
    {
        m_statusLabel->setText(ks::i18n::sourceText(
            QStringLiteral("目标域槽位不是合法的十进制数。")));
        return;
    }
    unsigned long long address = 0;
    if (!parseHex(m_addressEdit->text(), &address))
    {
        m_statusLabel->setText(ks::i18n::sourceText(
            QStringLiteral("物理起始地址不是合法的十六进制数。")));
        return;
    }
    unsigned long long length = 0;
    if (!parseHex(m_lengthEdit->text(), &length) || length == 0)
    {
        m_statusLabel->setText(ks::i18n::sourceText(
            QStringLiteral("长度不是合法的非零十六进制数。")));
        return;
    }
    unsigned long denied = 0;
    if (m_denyReadBox->isChecked())
    {
        denied |= KSWORD_ARK_HVM_EPT_ACCESS_READ;
    }
    if (m_denyWriteBox->isChecked())
    {
        denied |= KSWORD_ARK_HVM_EPT_ACCESS_WRITE;
    }
    if (m_denyExecuteBox->isChecked())
    {
        denied |= KSWORD_ARK_HVM_EPT_ACCESS_EXECUTE;
    }
    if (denied == 0)
    {
        m_statusLabel->setText(ks::i18n::sourceText(
            QStringLiteral("至少要勾选一项要拿掉的权限。")));
        return;
    }

    setBusy(true);
    QPointer<KvmDomainDialog> safeThis(this);
    std::thread([safeThis, domainIndex, address, length, denied]() {
        const ksword::kvm::KvmDomainResult result =
            ksword::kvm::restrictDomain(
                domainIndex,
                address,
                length,
                denied);
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
                safeThis->refreshDomains();
            },
            Qt::QueuedConnection);
    }).detach();
}

void KvmDomainDialog::startReset()
{
    if (m_busy)
    {
        return;
    }
    setBusy(true);
    QPointer<KvmDomainDialog> safeThis(this);
    std::thread([safeThis]() {
        const ksword::kvm::KvmDomainResult result =
            ksword::kvm::resetDomains();
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
                safeThis->refreshDomains();
            },
            Qt::QueuedConnection);
    }).detach();
}
