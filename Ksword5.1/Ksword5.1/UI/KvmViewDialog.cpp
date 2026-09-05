#include "KvmViewDialog.h"

#include "KvmControl.h"
#include "../Internationalization/LanguageManager.h"

#include <QComboBox>
#include <QFontDatabase>
#include <QFormLayout>
#include <QGridLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QPointer>
#include <QPushButton>
#include <QTableWidget>
#include <QVBoxLayout>

#include <thread>

namespace
{
    // 影子页正好一页，显式内容必须填满它。
    constexpr int kShadowPageBytes =
        static_cast<int>(KSWORD_ARK_HVM_VIEW_PAGE_BYTES);

    // parseHexPage：把十六进制文本解析成不超过一页的字节，并右侧补零到整页。
    bool parseHexPage(const QString& text, QByteArray* pageOut)
    {
        QString compact;
        compact.reserve(text.size());
        for (const QChar character : text)
        {
            if (character.isSpace())
            {
                continue;
            }
            if (!isxdigit(character.toLatin1()))
            {
                return false;
            }
            compact.append(character);
        }
        if (compact.isEmpty() || (compact.size() % 2) != 0)
        {
            return false;
        }
        if (compact.size() / 2 > kShadowPageBytes)
        {
            return false;
        }
        QByteArray bytes;
        bytes.reserve(compact.size() / 2);
        for (int index = 0; index < compact.size(); index += 2)
        {
            bool converted = false;
            const unsigned int value =
                compact.mid(index, 2).toUInt(&converted, 16);
            if (!converted)
            {
                return false;
            }
            bytes.append(static_cast<char>(value & 0xFFu));
        }
        // 驱动按整页拷贝，不足的部分补零而不是让它读到未初始化数据。
        bytes.append(kShadowPageBytes - bytes.size(), '\0');
        *pageOut = bytes;
        return true;
    }

    // describeKind：把视图类型翻译成一句话。
    QString describeKind(const unsigned long kind)
    {
        return kind == KSWORD_ARK_HVM_VIEW_KIND_CLOAK
            ? ks::i18n::sourceText(QStringLiteral("隐藏：执行走真实页，读写走影子"))
            : ks::i18n::sourceText(QStringLiteral("Hook：读写走真实页，执行走影子"));
    }
}

KvmViewDialog::KvmViewDialog(QWidget* const parent)
    : QDialog(parent)
{
    setWindowTitle(ks::i18n::sourceText(QStringLiteral("KVM EPT 分离视图")));
    setObjectName(QStringLiteral("KvmViewDialog"));
    buildUi();
    updateEnabledState();
    refreshViews();
}

void KvmViewDialog::buildUi()
{
    QVBoxLayout* const rootLayout = new QVBoxLayout(this);

    QLabel* const hintLabel = new QLabel(
        ks::i18n::sourceText(QStringLiteral(
            "视图靠翻转共享 EPT 叶项实现，只能在单处理器拓扑且未常驻时安装或移除。")),
        this);
    hintLabel->setWordWrap(true);
    rootLayout->addWidget(hintLabel);

    QFormLayout* const formLayout = new QFormLayout();
    m_kindBox = new QComboBox(this);
    m_kindBox->addItem(
        ks::i18n::sourceText(QStringLiteral("隐藏（读写看影子）")),
        static_cast<unsigned int>(KSWORD_ARK_HVM_VIEW_KIND_CLOAK));
    m_kindBox->addItem(
        ks::i18n::sourceText(QStringLiteral("Hook（执行看影子）")),
        static_cast<unsigned int>(KSWORD_ARK_HVM_VIEW_KIND_HOOK));
    formLayout->addRow(
        ks::i18n::sourceText(QStringLiteral("视图类型")),
        m_kindBox);

    m_addressEdit = new QLineEdit(this);
    m_addressEdit->setPlaceholderText(QStringLiteral("0x1000"));
    formLayout->addRow(
        ks::i18n::sourceText(QStringLiteral("目标物理页（十六进制，页对齐）")),
        m_addressEdit);

    m_seedBox = new QComboBox(this);
    m_seedBox->addItem(
        ks::i18n::sourceText(QStringLiteral("影子填零")), 0);
    m_seedBox->addItem(
        ks::i18n::sourceText(QStringLiteral("冻结目标页当前内容")), 1);
    m_seedBox->addItem(
        ks::i18n::sourceText(QStringLiteral("使用下方十六进制内容")), 2);
    formLayout->addRow(
        ks::i18n::sourceText(QStringLiteral("影子来源")),
        m_seedBox);
    rootLayout->addLayout(formLayout);

    m_shadowEdit = new QPlainTextEdit(this);
    m_shadowEdit->setFont(
        QFontDatabase::systemFont(QFontDatabase::FixedFont));
    m_shadowEdit->setPlaceholderText(
        ks::i18n::sourceText(QStringLiteral(
            "影子页内容，十六进制字节；不足一页的部分自动补零")));
    m_shadowEdit->setMaximumHeight(110);
    rootLayout->addWidget(m_shadowEdit);

    m_viewTable = new QTableWidget(0, 5, this);
    m_viewTable->setHorizontalHeaderLabels(QStringList()
        << ks::i18n::sourceText(QStringLiteral("编号"))
        << ks::i18n::sourceText(QStringLiteral("类型"))
        << ks::i18n::sourceText(QStringLiteral("目标物理页"))
        << ks::i18n::sourceText(QStringLiteral("影子物理页"))
        << ks::i18n::sourceText(QStringLiteral("翻转次数")));
    m_viewTable->horizontalHeader()->setStretchLastSection(true);
    m_viewTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_viewTable->setSelectionMode(QAbstractItemView::SingleSelection);
    m_viewTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    rootLayout->addWidget(m_viewTable, 1);

    QGridLayout* const buttonLayout = new QGridLayout();
    m_addButton = new QPushButton(
        ks::i18n::sourceText(QStringLiteral("安装视图")), this);
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
        refreshViews();
    });
    resize(720, 520);
}

void KvmViewDialog::updateEnabledState()
{
    const bool writeAllowed = ksword::kvm::isWriteAccessEnabled();
    const QString writeHint = writeAllowed
        ? QString()
        : ks::i18n::sourceText(QStringLiteral(
            "R-1 写权限未开启：在 KVM 按钮右键菜单中开启后才能安装或移除视图"));
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
}

void KvmViewDialog::setBusy(const bool busy)
{
    m_busy = busy;
    updateEnabledState();
}

void KvmViewDialog::refreshViews()
{
    if (m_busy)
    {
        return;
    }
    setBusy(true);
    QPointer<KvmViewDialog> safeThis(this);
    std::thread([safeThis]() {
        const ksword::kvm::KvmViewResult result = ksword::kvm::listViews();
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
                QTableWidget* const table = safeThis->m_viewTable;
                table->setRowCount(result.views.size());
                for (int row = 0; row < result.views.size(); ++row)
                {
                    const auto& entry = result.views.at(row);
                    table->setItem(row, 0, new QTableWidgetItem(
                        QString::number(entry.viewId)));
                    table->setItem(row, 1, new QTableWidgetItem(
                        describeKind(entry.kind)));
                    table->setItem(row, 2, new QTableWidgetItem(
                        QStringLiteral("0x%1")
                            .arg(entry.physicalAddress, 0, 16)));
                    table->setItem(row, 3, new QTableWidgetItem(
                        QStringLiteral("0x%1")
                            .arg(entry.shadowPhysicalAddress, 0, 16)));
                    table->setItem(row, 4, new QTableWidgetItem(
                        QString::number(entry.flipCount)));
                }
                safeThis->m_statusLabel->setText(
                    ks::i18n::sourceText(QStringLiteral("已安装 %1 条视图。"))
                        .arg(result.viewCount));
            },
            Qt::QueuedConnection);
    }).detach();
}

void KvmViewDialog::startAdd()
{
    QString addressText = m_addressEdit->text().trimmed();
    if (addressText.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive))
    {
        addressText = addressText.mid(2);
    }
    bool converted = false;
    const unsigned long long address =
        addressText.toULongLong(&converted, 16);
    if (!converted)
    {
        m_statusLabel->setText(ks::i18n::sourceText(
            QStringLiteral("目标物理页不是合法的十六进制数。")));
        return;
    }

    const unsigned long kind =
        m_kindBox->currentData().toUInt();
    const int seedIndex = m_seedBox->currentIndex();
    ksword::kvm::KvmViewShadowSeed seed =
        ksword::kvm::KvmViewShadowSeed::Zero;
    QByteArray shadow;
    if (seedIndex == 1)
    {
        seed = ksword::kvm::KvmViewShadowSeed::FromTarget;
    }
    else if (seedIndex == 2)
    {
        seed = ksword::kvm::KvmViewShadowSeed::Explicit;
        if (!parseHexPage(m_shadowEdit->toPlainText(), &shadow))
        {
            m_statusLabel->setText(ks::i18n::sourceText(QStringLiteral(
                "影子内容必须是成对的十六进制字节，且不超过一页。")));
            return;
        }
    }

    setBusy(true);
    m_statusLabel->setText(
        ks::i18n::sourceText(QStringLiteral("正在安装视图...")));
    QPointer<KvmViewDialog> safeThis(this);
    std::thread([safeThis, kind, address, seed, shadow]() {
        const ksword::kvm::KvmViewResult result =
            ksword::kvm::addView(kind, address, seed, shadow);
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
                        QStringLiteral("已安装视图，编号 %1。"))
                        .arg(result.viewId)
                    : result.message);
                safeThis->refreshViews();
            },
            Qt::QueuedConnection);
    }).detach();
}

void KvmViewDialog::startRemove()
{
    const int row = m_viewTable->currentRow();
    if (row < 0 || m_viewTable->item(row, 0) == nullptr)
    {
        m_statusLabel->setText(
            ks::i18n::sourceText(QStringLiteral("请先在表中选择一条视图。")));
        return;
    }
    const unsigned long viewId =
        m_viewTable->item(row, 0)->text().toULong();

    setBusy(true);
    m_statusLabel->setText(
        ks::i18n::sourceText(QStringLiteral("正在移除视图...")));
    QPointer<KvmViewDialog> safeThis(this);
    std::thread([safeThis, viewId]() {
        const ksword::kvm::KvmViewResult result =
            ksword::kvm::removeView(viewId);
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
                safeThis->refreshViews();
            },
            Qt::QueuedConnection);
    }).detach();
}

void KvmViewDialog::startClear()
{
    setBusy(true);
    m_statusLabel->setText(
        ks::i18n::sourceText(QStringLiteral("正在移除全部视图...")));
    QPointer<KvmViewDialog> safeThis(this);
    std::thread([safeThis]() {
        const ksword::kvm::KvmViewResult result = ksword::kvm::clearViews();
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
                safeThis->refreshViews();
            },
            Qt::QueuedConnection);
    }).detach();
}
