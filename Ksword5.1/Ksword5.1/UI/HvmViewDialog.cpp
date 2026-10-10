#include "HvmViewDialog.h"
#include "./SecondaryPageLayout.h"
#include "./ToolbarMetrics.h"
#include "./TableInteractionSupport.h"
#include "./VisibleTableWidget.h"

#include "HvmControl.h"
#include "MemoryWorkbench/SnapshotWorkbenchWidget.h"
#include "MemoryWorkbench/HexView.h"
#include "UI_All.h"
#include "../Internationalization/LanguageManager.h"
#include "../../../shared/evidence/HookPatchCompose.h"
#include "../../../shared/evidence/MemoryAddressInput.h"

#include <QComboBox>
#include <QCoreApplication>
#include <QFormLayout>
#include <QGridLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QHBoxLayout>
#include <QPointer>
#include <QPushButton>
#include <QTableWidget>
#include <QVBoxLayout>

#include <algorithm>
#include <thread>

namespace
{
    // 驱动安装接口始终接收整页；用户输入只是一段原址补丁。
    constexpr int kShadowPageBytes =
        static_cast<int>(KSWORD_ARK_HVM_VIEW_PAGE_BYTES);
    static_assert(kShadowPageBytes == Ksword::Evidence::kPatchPageBytes);
    // 与驱动 KSW_HVM_MAX_MAPPED_PHYSICAL 的 EPT 映射上界一致。
    constexpr unsigned long long kMaxViewPhysicalAddress = 1ULL << 46;

    bool parseTargetAddress(const QString& text, unsigned long long* addressOut)
    {
        const QByteArray input = text.trimmed().toLatin1();
        std::uint64_t address = 0;
        if (!Ksword::Evidence::ParseHexAddress(
                std::string_view(input.constData(),
                    static_cast<std::size_t>(input.size())), address))
        {
            return false;
        }
        *addressOut = address;
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

HvmViewDialog::HvmViewDialog(QWidget* const parent)
    : QDialog(parent)
{
    setWindowTitle(ks::i18n::sourceText(QStringLiteral("HVM EPT 分离视图")));
    setObjectName(QStringLiteral("HvmViewDialog"));
    buildUi();
    updateEnabledState();
    refreshViews();
    ks::ui::applyResponsiveWindowGeometry(
        this, parent, QSize(1120, 820), QSize(640, 480));
}

void HvmViewDialog::buildUi()
{
    ks::ui::StyleSecondaryWindow(this);
    QVBoxLayout* const rootLayout = new QVBoxLayout(this);
    ks::ui::StyleSecondaryContentLayout(rootLayout);
    rootLayout->setSizeConstraint(QLayout::SetNoConstraint);

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

    m_addressKindBox = new QComboBox(this);
    m_addressKindBox->addItem(
        ks::i18n::sourceText(QStringLiteral("虚拟地址")), true);
    m_addressKindBox->addItem(
        ks::i18n::sourceText(QStringLiteral("物理地址")), false);
    formLayout->addRow(
        ks::i18n::sourceText(QStringLiteral("地址类型")), m_addressKindBox);

    m_addressEdit = new QLineEdit(this);
    m_addressEdit->setPlaceholderText(QStringLiteral("0x1000"));
    m_addressEdit->setToolTip(ks::i18n::sourceText(QStringLiteral(
        "目标地址无需页对齐；读取后在统一编辑器内修改所在页，安装前再次核对目标映射和原字节。")));
    formLayout->addRow(
        ks::i18n::sourceText(QStringLiteral("目标地址（十六进制）")),
        m_addressEdit);

    m_processIdEdit = new QLineEdit(
        QString::number(QCoreApplication::applicationPid()), this);
    formLayout->addRow(
        ks::i18n::sourceText(QStringLiteral("目标 PID（十进制）")),
        m_processIdEdit);

    m_cr3Edit = new QLineEdit(this);
    m_cr3Edit->setPlaceholderText(ks::i18n::sourceText(QStringLiteral(
        "留空：自动获取目标进程 CR3")));
    m_cr3Edit->setToolTip(ks::i18n::sourceText(QStringLiteral(
        "留空时按目标 PID 自动计算 CR3；输入非零十六进制值时使用自定义 CR3，目标 PID 不参与解析。")));
    formLayout->addRow(
        ks::i18n::sourceText(QStringLiteral("CR3（十六进制，可选）")),
        m_cr3Edit);

    m_seedBox = new QComboBox(this);
    m_seedBox->addItem(
        ks::i18n::sourceText(QStringLiteral("冻结目标页当前内容")),
        static_cast<int>(ksword::hvm::HvmViewShadowSeed::FromTarget));
    m_seedBox->addItem(
        ks::i18n::sourceText(QStringLiteral("复制目标页并应用编辑器中的修改")),
        static_cast<int>(ksword::hvm::HvmViewShadowSeed::Explicit));
    m_seedBox->addItem(
        ks::i18n::sourceText(QStringLiteral("整页填零（会替换全部 4096 字节）")),
        static_cast<int>(ksword::hvm::HvmViewShadowSeed::Zero));
    formLayout->addRow(
        ks::i18n::sourceText(QStringLiteral("影子来源")),
        m_seedBox);
    ks::ui::StyleSecondaryForm(formLayout, 186);
    rootLayout->addLayout(formLayout);

    m_targetHintLabel = new QLabel(this);
    m_targetHintLabel->setWordWrap(true);
    rootLayout->addWidget(m_targetHintLabel);

    QHBoxLayout* const shadowTools = new QHBoxLayout();
    m_readShadowButton = new QPushButton(
        ks::i18n::sourceText(QStringLiteral("读取目标页")), this);
    m_discardShadowButton = new QPushButton(
        ks::i18n::sourceText(QStringLiteral("放弃修改")), this);
    shadowTools->addWidget(m_readShadowButton);
    shadowTools->addWidget(m_discardShadowButton);
    shadowTools->addStretch(1);
    ks::ui::NormalizeToolbarRow(shadowTools);
    rootLayout->addLayout(shadowTools);
    m_shadowEditor = new ks::ui::SnapshotWorkbenchWidget(this);
    m_shadowEditor->setEditable(false);
    m_shadowEditor->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Expanding);
    rootLayout->addWidget(m_shadowEditor, 2);

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
    // 当前规则清单与本页事务动作配套，不再叠加快照/对比工具栏。
    ks::ui::SetTableActionBarMode(m_viewTable, ks::ui::TableActionBarMode::None);
    rootLayout->addWidget(m_viewTable, 1);

    // 参数与结果保持同屏；动作和状态由独立的底部分隔区承载。
    auto* const footer = new QWidget(this);
    auto* const footerLayout = new QVBoxLayout(footer);
    QGridLayout* const buttonLayout = new QGridLayout();
    buttonLayout->setHorizontalSpacing(8);
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
    for (QPushButton* button : { m_addButton, m_removeButton, m_clearButton, m_refreshButton })
    {
        ks::ui::NormalizeToolbarControl(button);
    }
    footerLayout->addLayout(buttonLayout);

    m_statusLabel = new QLabel(QString(), this);
    m_statusLabel->setWordWrap(true);
    footerLayout->addWidget(m_statusLabel);
    ks::ui::StyleSecondaryFooter(footer);
    rootLayout->addWidget(footer);

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
    connect(m_seedBox, &QComboBox::currentIndexChanged, this, [this]() {
        updateShadowPreview();
        updateEnabledState();
    });
    connect(m_addressEdit, &QLineEdit::textChanged, this, [this]() {
        invalidateShadowSnapshot();
        updateTargetHint();
    });
    connect(m_addressKindBox, &QComboBox::currentIndexChanged,
        this, [this]() {
            invalidateShadowSnapshot();
            updateEnabledState();
            updateTargetHint();
        });
    connect(m_cr3Edit, &QLineEdit::textChanged, this, [this]() {
        invalidateShadowSnapshot();
        updateEnabledState();
        updateTargetHint();
    });
    connect(m_processIdEdit, &QLineEdit::textChanged, this, [this]() {
        invalidateShadowSnapshot();
        updateTargetHint();
    });
    connect(m_readShadowButton, &QPushButton::clicked,
        this, [this]() { startReadShadow(); });
    connect(m_discardShadowButton, &QPushButton::clicked, this, [this]() {
        m_shadowEditor->discardChanges();
        updateShadowPreview();
        updateEnabledState();
    });
    connect(m_shadowEditor, &ks::ui::SnapshotWorkbenchWidget::bytesChanged,
        this, [this]() { updateEnabledState(); });
    updateTargetHint();
}

void HvmViewDialog::updateEnabledState()
{
    m_kindBox->setEnabled(!m_busy);
    const bool explicitShadow = m_seedBox->currentData().toInt() ==
        static_cast<int>(ksword::hvm::HvmViewShadowSeed::Explicit);
    const bool dirty = explicitShadow && m_shadowEditor->hasChanges();
    const bool targetEnabled = !m_busy && !dirty;
    m_addressKindBox->setEnabled(targetEnabled);
    m_seedBox->setEnabled(targetEnabled);
    m_addressEdit->setEnabled(targetEnabled);
    const bool virtualAddress = m_addressKindBox->currentData().toBool();
    m_cr3Edit->setEnabled(targetEnabled && virtualAddress);
    m_processIdEdit->setEnabled(targetEnabled && virtualAddress &&
        m_cr3Edit->text().trimmed().isEmpty());
    m_shadowEditor->setEnabled(!m_busy);
    m_shadowEditor->setEditable(!m_busy && explicitShadow && m_shadowSnapshotValid);
    m_readShadowButton->setEnabled(targetEnabled);
    m_discardShadowButton->setEnabled(!m_busy && dirty);
    m_viewTable->setEnabled(!m_busy);
    const bool writeAllowed = ksword::hvm::isWriteAccessEnabled();
    const QString writeHint = writeAllowed
        ? QString()
        : ks::i18n::sourceText(QStringLiteral(
            "R-1 写权限未开启：在 HVM 按钮右键菜单中开启后才能安装或移除视图"));
    if (m_addButton != nullptr)
    {
        m_addButton->setEnabled(writeAllowed && !m_busy &&
            (!explicitShadow || (m_shadowSnapshotValid && dirty)));
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

void HvmViewDialog::updateTargetHint()
{
    unsigned long long address = 0;
    const bool virtualAddress = m_addressKindBox->currentData().toBool();
    if (!parseTargetAddress(m_addressEdit->text(), &address) ||
        (!virtualAddress && address >= kMaxViewPhysicalAddress))
    {
        m_targetHintLabel->clear();
        return;
    }
    const unsigned long long page = address &
        ~(static_cast<unsigned long long>(kShadowPageBytes) - 1ULL);
    const unsigned long long offset = address - page;
    if (virtualAddress)
    {
        m_targetHintLabel->setText(ks::i18n::sourceText(QStringLiteral(
            "虚拟目标：0x%1；安装前将解析物理页，并保留页内偏移 0x%2。"))
            .arg(address, 0, 16).arg(offset, 0, 16));
        return;
    }
    m_targetHintLabel->setText(ks::i18n::sourceText(QStringLiteral(
        "目标所在页：0x%1；页内偏移：0x%2（%3 字节）。"))
        .arg(page, 0, 16).arg(offset, 0, 16).arg(offset));
}

void HvmViewDialog::setBusy(const bool busy)
{
    m_busy = busy;
    updateEnabledState();
}

void HvmViewDialog::refreshViews(const bool preserveStatus)
{
    if (m_busy)
    {
        return;
    }
    setBusy(true);
    const QString previousStatus = preserveStatus
        ? m_statusLabel->text() : QString();
    QPointer<HvmViewDialog> safeThis(this);
    std::thread([safeThis, previousStatus]() {
        const ksword::hvm::HvmViewResult result = ksword::hvm::listViews();
        if (safeThis == nullptr)
        {
            return;
        }
        QMetaObject::invokeMethod(
            safeThis,
            [safeThis, result, previousStatus]() {
                if (safeThis == nullptr)
                {
                    return;
                }
                safeThis->setBusy(false);
                if (!result.ok)
                {
                    safeThis->m_statusLabel->setText(previousStatus.isEmpty()
                        ? result.message
                        : previousStatus + QStringLiteral("\n") + result.message);
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
                safeThis->m_statusLabel->setText(previousStatus.isEmpty()
                    ? ks::i18n::sourceText(QStringLiteral("已安装 %1 条视图。"))
                        .arg(result.viewCount)
                    : previousStatus);
            },
            Qt::QueuedConnection);
    }).detach();
}

bool HvmViewDialog::parseTargetRequest(
    unsigned long long* const addressOut, bool* const virtualOut,
    unsigned long long* const cr3Out, unsigned long* const processIdOut)
{
    unsigned long long address = 0;
    if (!parseTargetAddress(m_addressEdit->text(), &address))
    {
        m_statusLabel->setText(ks::i18n::sourceText(
            QStringLiteral("目标地址不是合法的十六进制数。")));
        return false;
    }
    const bool virtualAddress = m_addressKindBox->currentData().toBool();
    const QString outOfRangeText = ks::i18n::sourceText(QStringLiteral(
        "目标所在页超出 EPT 映射范围：物理地址必须小于 64 TiB。"));
    if (!virtualAddress && address >= kMaxViewPhysicalAddress)
    {
        m_statusLabel->setText(outOfRangeText);
        return false;
    }
    unsigned long long cr3 = 0;
    unsigned long processId = 0;
    if (virtualAddress)
    {
        if (!m_cr3Edit->text().trimmed().isEmpty())
        {
            if (!parseTargetAddress(m_cr3Edit->text(), &cr3) || cr3 == 0ULL)
            {
                m_statusLabel->setText(ks::i18n::sourceText(QStringLiteral(
                    "自定义 CR3 必须是非零十六进制地址；留空可自动计算。")));
                return false;
            }
        }
        else
        {
            const QString pidText = m_processIdEdit->text().trimmed();
            bool validPid = !pidText.isEmpty();
            for (const QChar digit : pidText)
            {
                validPid = validPid && digit >= QLatin1Char('0') &&
                    digit <= QLatin1Char('9');
            }
            bool converted = false;
            const unsigned long long pid = pidText.toULongLong(&converted, 10);
            if (!validPid || !converted || pid == 0 || pid > 0xFFFFFFFFULL)
            {
                m_statusLabel->setText(ks::i18n::sourceText(QStringLiteral(
                    "目标 PID 必须是非零的 32 位十进制数。")));
                return false;
            }
            processId = static_cast<unsigned long>(pid);
        }
    }
    *addressOut = address;
    *virtualOut = virtualAddress;
    *cr3Out = cr3;
    *processIdOut = processId;
    return true;
}

void HvmViewDialog::invalidateShadowSnapshot()
{
    ++m_shadowReadSequence;
    m_shadowSnapshotValid = false;
    m_shadowEditor->clear();
    updateEnabledState();
}

void HvmViewDialog::updateShadowPreview()
{
    if (!m_shadowSnapshotValid)
    {
        return;
    }
    m_shadowEditor->discardChanges();
    if (m_seedBox->currentData().toInt() ==
        static_cast<int>(ksword::hvm::HvmViewShadowSeed::Zero))
    {
        m_shadowEditor->hexEditor()->setBuffer(
            m_shadowEditor->baseAddress(), QByteArray(kShadowPageBytes, '\0'));
        m_shadowEditor->refreshFromHexEditor();
    }
}

void HvmViewDialog::startReadShadow()
{
    if (m_busy || (m_seedBox->currentData().toInt() ==
            static_cast<int>(ksword::hvm::HvmViewShadowSeed::Explicit) &&
        m_shadowEditor->hasChanges()))
    {
        return;
    }
    unsigned long long address = 0;
    unsigned long long cr3 = 0;
    unsigned long processId = 0;
    bool virtualAddress = false;
    if (!parseTargetRequest(&address, &virtualAddress, &cr3, &processId))
    {
        return;
    }
    const auto architecture = m_shadowEditor->currentArchitecture();
    const unsigned long long sequence = ++m_shadowReadSequence;
    const QString incompletePageText = ks::i18n::sourceText(QStringLiteral(
        "无法完整复制目标页（0x%1）：请求 %2 字节，收到 %3 字节。%4 未安装视图。"));
    const QString outOfRangeText = ks::i18n::sourceText(QStringLiteral(
        "目标所在页超出 EPT 映射范围：物理地址必须小于 64 TiB。"));
    setBusy(true);
    m_statusLabel->setText(ks::i18n::sourceText(QStringLiteral("正在读取目标页...")));
    QPointer<HvmViewDialog> safeThis(this);
    std::thread([safeThis, sequence, address, virtualAddress, cr3, processId,
                    architecture, incompletePageText, outOfRangeText]() {
        unsigned long long physicalAddress = address;
        QString failure;
        if (virtualAddress)
        {
            const auto translated = ksword::hvm::translate(cr3, address, processId);
            if (!translated.ok)
            {
                failure = translated.message;
            }
            else
            {
                physicalAddress = translated.physicalAddress;
            }
        }
        const unsigned long long physicalPage = physicalAddress &
            ~(static_cast<unsigned long long>(kShadowPageBytes) - 1ULL);
        if (failure.isEmpty() && physicalAddress >= kMaxViewPhysicalAddress)
        {
            failure = outOfRangeText;
        }
        QByteArray page;
        while (failure.isEmpty() && page.size() < kShadowPageBytes)
        {
            if (safeThis == nullptr)
            {
                return;
            }
            const unsigned long chunkBytes = static_cast<unsigned long>((std::min)(
                kShadowPageBytes - static_cast<int>(page.size()),
                static_cast<int>(KSWORD_ARK_HVM_MEMORY_MAX_BYTES)));
            const unsigned long long chunkAddress = physicalPage +
                static_cast<unsigned long long>(page.size());
            const auto result = ksword::hvm::readPhysical(chunkAddress, chunkBytes);
            if (!result.ok || result.data.size() != static_cast<qsizetype>(chunkBytes))
            {
                failure = incompletePageText.arg(chunkAddress, 0, 16).arg(chunkBytes)
                    .arg(result.data.size()).arg(result.message);
                break;
            }
            page.append(result.data);
        }
        if (safeThis == nullptr)
        {
            return;
        }
        QMetaObject::invokeMethod(safeThis,
            [safeThis, sequence, address, virtualAddress, cr3, processId, architecture,
                physicalAddress, physicalPage, page, failure]() {
                if (safeThis == nullptr)
                {
                    return;
                }
                safeThis->setBusy(false);
                if (sequence != safeThis->m_shadowReadSequence)
                {
                    return;
                }
                if (!failure.isEmpty() || page.size() != kShadowPageBytes)
                {
                    safeThis->invalidateShadowSnapshot();
                    safeThis->m_statusLabel->setText(failure);
                    return;
                }
                safeThis->m_shadowPhysicalAddress = physicalAddress;
                safeThis->m_shadowSnapshotValid = true;
                const unsigned long long displayPage = virtualAddress
                    ? address & ~(static_cast<unsigned long long>(kShadowPageBytes) - 1ULL)
                    : physicalPage;
                const QString identity = QStringLiteral("hvm_view/%1/%2/%3/%4/%5")
                    .arg(virtualAddress).arg(address, 0, 16).arg(cr3, 0, 16)
                    .arg(processId).arg(physicalPage, 0, 16);
                safeThis->m_shadowEditor->setSnapshot(
                    page, displayPage, architecture, address, identity);
                safeThis->updateShadowPreview();
                safeThis->updateEnabledState();
                safeThis->m_statusLabel->setText(ks::i18n::sourceText(QStringLiteral(
                    "目标页已读取：物理页 0x%1。编辑器中的修改仅在安装视图时提交。"))
                    .arg(physicalPage, 0, 16));
            }, Qt::QueuedConnection);
    }).detach();
}

void HvmViewDialog::startAdd()
{
    if (m_busy)
    {
        return;
    }
    unsigned long long address = 0;
    unsigned long long cr3 = 0;
    unsigned long processId = 0;
    bool virtualAddress = false;
    if (!parseTargetRequest(&address, &virtualAddress, &cr3, &processId))
    {
        return;
    }
    const QString outOfRangeText = ks::i18n::sourceText(QStringLiteral(
        "目标所在页超出 EPT 映射范围：物理地址必须小于 64 TiB。"));

    const unsigned long kind =
        m_kindBox->currentData().toUInt();
    const auto seed = static_cast<ksword::hvm::HvmViewShadowSeed>(
        m_seedBox->currentData().toInt());
    QByteArray stagedShadow;
    QByteArray originalPage;
    const unsigned long long expectedPhysical = m_shadowPhysicalAddress;
    if (seed == ksword::hvm::HvmViewShadowSeed::Explicit)
    {
        if (!m_shadowSnapshotValid || !m_shadowEditor->hasChanges())
        {
            m_statusLabel->setText(ks::i18n::sourceText(QStringLiteral(
                "请先读取目标页并在编辑器中修改，再安装视图。")));
            return;
        }
        stagedShadow = m_shadowEditor->data();
        originalPage = m_shadowEditor->originalBytes();
        if (stagedShadow.size() != kShadowPageBytes || originalPage.size() != kShadowPageBytes)
        {
            m_statusLabel->setText(ks::i18n::sourceText(QStringLiteral(
                "无法构造完整影子页，未安装视图。")));
            return;
        }
    }

    // 线程只使用已翻译的模板，避免后台读取可变语言状态。
    const QString incompletePageText = ks::i18n::sourceText(QStringLiteral(
        "无法完整复制目标页（0x%1）：请求 %2 字节，收到 %3 字节。%4 未安装视图。"));
    const QString staleSnapshotText = ks::i18n::sourceText(QStringLiteral(
        "目标映射或原页字节已变化，已中止安装。请放弃修改、重新读取后再编辑。"));
    const QString resolvedTargetText = ks::i18n::sourceText(QStringLiteral(
        "虚拟目标：0x%1 → 物理地址：0x%2；所在页：0x%3；页内偏移：0x%4。"));
    setBusy(true);
    m_statusLabel->setText(seed == ksword::hvm::HvmViewShadowSeed::Zero
        ? ks::i18n::sourceText(QStringLiteral("正在安装视图..."))
        : ks::i18n::sourceText(QStringLiteral("正在复制目标页并安装视图...")));
    QPointer<HvmViewDialog> safeThis(this);
    std::thread([safeThis, kind, address, virtualAddress, cr3, processId,
                    seed, stagedShadow, originalPage, expectedPhysical,
                    incompletePageText, staleSnapshotText, outOfRangeText, resolvedTargetText]() {
        ksword::hvm::HvmViewResult result;
        unsigned long long physicalAddress = address;
        bool ready = true;
        if (virtualAddress)
        {
            if (safeThis == nullptr)
            {
                return;
            }
            const auto translated = ksword::hvm::translate(cr3, address, processId);
            if (!translated.ok)
            {
                result.message = translated.message;
                ready = false;
            }
            else
            {
                physicalAddress = translated.physicalAddress;
            }
        }
        const unsigned long long pageAddress = physicalAddress &
            ~(static_cast<unsigned long long>(kShadowPageBytes) - 1ULL);
        const std::uint32_t pageOffset =
            static_cast<std::uint32_t>(physicalAddress - pageAddress);
        const QString resolvedTargetHint = virtualAddress && ready
            ? resolvedTargetText.arg(address, 0, 16).arg(physicalAddress, 0, 16)
                .arg(pageAddress, 0, 16).arg(pageOffset, 0, 16)
            : QString();
        if (ready && physicalAddress >= kMaxViewPhysicalAddress)
        {
            result.message = outOfRangeText;
            ready = false;
        }
        if (ready && seed == ksword::hvm::HvmViewShadowSeed::Explicit &&
            physicalAddress != expectedPhysical)
        {
            result.message = staleSnapshotText;
            ready = false;
        }
        QByteArray shadow;
        auto installSeed = seed;
        if (ready && seed != ksword::hvm::HvmViewShadowSeed::Zero)
        {
            // 原页必须读齐，短读和失败都不能用零字节凑成可安装的影子。
            shadow.reserve(kShadowPageBytes);
            while (shadow.size() < kShadowPageBytes)
            {
                if (safeThis == nullptr)
                {
                    return;
                }
                const int remaining = kShadowPageBytes -
                    static_cast<int>(shadow.size());
                const unsigned long chunkBytes = static_cast<unsigned long>(
                    (std::min)(remaining,
                        static_cast<int>(KSWORD_ARK_HVM_MEMORY_MAX_BYTES)));
                const unsigned long long chunkAddress = pageAddress +
                    static_cast<unsigned long long>(shadow.size());
                const auto read = ksword::hvm::readPhysical(
                    chunkAddress, chunkBytes);
                if (!read.ok || read.data.size() != static_cast<qsizetype>(chunkBytes))
                {
                    result.message = incompletePageText
                        .arg(chunkAddress, 0, 16).arg(chunkBytes)
                        .arg(read.data.size()).arg(read.message);
                    ready = false;
                    break;
                }
                shadow.append(read.data);
            }
            if (ready &&
                seed == ksword::hvm::HvmViewShadowSeed::Explicit)
            {
                if (shadow != originalPage)
                {
                    result.message = staleSnapshotText;
                    ready = false;
                }
                else
                {
                    shadow = stagedShadow;
                }
            }
            installSeed = ksword::hvm::HvmViewShadowSeed::Explicit;
        }
        if (safeThis == nullptr)
        {
            return;
        }
        if (ready)
        {
            result = ksword::hvm::addView(
                kind, pageAddress, installSeed, shadow);
        }
        if (safeThis == nullptr)
        {
            return;
        }
        QMetaObject::invokeMethod(
            safeThis,
            [safeThis, result, resolvedTargetHint]() {
                if (safeThis == nullptr)
                {
                    return;
                }
                safeThis->setBusy(false);
                if (!resolvedTargetHint.isEmpty())
                {
                    safeThis->m_targetHintLabel->setText(resolvedTargetHint);
                }
                safeThis->m_statusLabel->setText(result.ok
                    ? ks::i18n::sourceText(
                        QStringLiteral("已安装视图，编号 %1。"))
                        .arg(result.viewId)
                    : result.message);
                if (result.ok)
                {
                    safeThis->refreshViews(true);
                }
            },
            Qt::QueuedConnection);
    }).detach();
}

void HvmViewDialog::startRemove()
{
    if (m_busy)
    {
        return;
    }
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
    QPointer<HvmViewDialog> safeThis(this);
    std::thread([safeThis, viewId]() {
        const ksword::hvm::HvmViewResult result =
            ksword::hvm::removeView(viewId);
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
                if (result.ok)
                {
                    safeThis->refreshViews(true);
                }
            },
            Qt::QueuedConnection);
    }).detach();
}

void HvmViewDialog::startClear()
{
    if (m_busy)
    {
        return;
    }
    setBusy(true);
    m_statusLabel->setText(
        ks::i18n::sourceText(QStringLiteral("正在移除全部视图...")));
    QPointer<HvmViewDialog> safeThis(this);
    std::thread([safeThis]() {
        const ksword::hvm::HvmViewResult result = ksword::hvm::clearViews();
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
                if (result.ok)
                {
                    safeThis->refreshViews(true);
                }
            },
            Qt::QueuedConnection);
    }).detach();
}
