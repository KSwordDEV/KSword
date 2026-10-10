#include "KernelTextIntegrityTab.h"
#include "../UI/PageControlStyle.h"
#include "../UI/ToolbarMetrics.h"

#include "KernelDock.h"
#include "../ArkDriverClient/ArkDriverClient.h"
#include "../Internationalization/LanguageManager.h"
#include "../UI/VisibleTableWidget.h"
#include "../theme.h"

#include <QAbstractItemView>
#include <QCheckBox>
#include <QComboBox>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMetaObject>
#include <QPointer>
#include <QPushButton>
#include <QShowEvent>
#include <QSplitter>
#include <QStringList>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QVBoxLayout>

#include <thread>
#include <utility>

using ksword::kernel_dock_internal::kernelText;
using ks::kernel::KernelCleanImageBaseline;
using ks::kernel::KernelTextDiffRange;
using ks::kernel::KernelTextIntegrityResult;
using ks::kernel::KernelTextScanOptions;

namespace
{
    enum ModuleColumn : int
    {
        ModuleColumnName = 0,
        ModuleColumnBase,
        ModuleColumnBackend,
        ModuleColumnSections,
        ModuleColumnScanned,
        ModuleColumnUnreadable,
        ModuleColumnDiffering,
        ModuleColumnKnown,
        ModuleColumnUnexplained,
        ModuleColumnTrust,
        ModuleColumnStatus,
        ModuleColumnCount
    };

    enum RangeColumn : int
    {
        RangeColumnModule = 0,
        RangeColumnSection,
        RangeColumnRva,
        RangeColumnAddress,
        RangeColumnLength,
        RangeColumnOrigin,
        RangeColumnClean,
        RangeColumnObserved,
        RangeColumnCount
    };

    QTableWidgetItem* readOnlyItem(const QString& text)
    {
        auto* item = new QTableWidgetItem(text);
        item->setFlags(item->flags() & ~Qt::ItemIsEditable);
        return item;
    }

    // setHeaderTip 作用：
    // - 输入 table/column/tipText：目标表格、列序号和悬停说明；
    // - 处理：把判定口径挂到它解释的那一列表头上；
    // - 返回：无，表头项缺失时静默跳过。
    void setHeaderTip(QTableWidget* table, const int column, const QString& tipText)
    {
        QTableWidgetItem* headerItem = table->horizontalHeaderItem(column);
        if (headerItem != nullptr)
        {
            headerItem->setToolTip(tipText);
        }
    }
}

KernelTextIntegrityTab::KernelTextIntegrityTab(QWidget* parent)
    : QWidget(parent)
{
    initializeUi();
}

KernelTextIntegrityTab::~KernelTextIntegrityTab()
{
    // 工作线程持有 cancelFlag 的共享所有权，这里只负责让它尽快退出。
    if (m_cancelFlag != nullptr)
    {
        m_cancelFlag->store(true);
    }
}

void KernelTextIntegrityTab::showEvent(QShowEvent* event)
{
    QWidget::showEvent(event);
    if (!m_firstScanStarted)
    {
        // 全量扫描代价较高，首次进入只准备界面，由用户主动触发。
        m_firstScanStarted = true;
        m_statusLabel->setText(
            kernelText(
                "kernel.text_integrity.status.idle",
                QStringLiteral("状态：点击“开始扫描”后逐模块比对可执行节")));
    }
}

void KernelTextIntegrityTab::initializeUi()
{
    auto* rootLayout = new QVBoxLayout(this);
    rootLayout->setContentsMargins(6, 6, 6, 6);
    rootLayout->setSpacing(6);

    auto* toolbar = new QHBoxLayout();
    m_scanButton = new QPushButton(
        kernelText("kernel.text_integrity.scan", QStringLiteral("开始扫描")),
        this);
    // 判定口径不占版面：挂在触发扫描的按钮上，谁要看谁悬停。
    m_scanButton->setToolTip(
        kernelText(
            "kernel.text_integrity.scan.tooltip",
            QStringLiteral("比对基准是磁盘净映像按当前加载基址重定位后的结果。")));
    m_scanButton->setStyleSheet(KswordTheme::ThemedButtonStyle());
    m_cancelButton = new QPushButton(
        kernelText("kernel.text_integrity.cancel", QStringLiteral("取消")),
        this);
    m_cancelButton->setStyleSheet(KswordTheme::ThemedButtonStyle());
    m_cancelButton->setEnabled(false);
    m_moduleFilterEdit = new QLineEdit(this);
    ks::ui::StyleSearchField(m_moduleFilterEdit);
    m_moduleFilterEdit->setClearButtonEnabled(true);
    m_moduleFilterEdit->setPlaceholderText(
        kernelText(
            "kernel.text_integrity.filter.placeholder",
            QStringLiteral("按模块名过滤，留空扫描全部已加载模块")));
    m_backendCombo = new QComboBox(this);
    for (const auto backend : {
             ksword::memory_backend::MemoryAccessBackend::StandardDriver,
             ksword::memory_backend::MemoryAccessBackend::Hvm})
    {
        m_backendCombo->addItem(
            ks::i18n::sourceText(ksword::memory_backend::backendDisplayName(backend)),
            static_cast<int>(backend));
    }
    m_backendCombo->setToolTip(
        kernelText(
            "kernel.text_integrity.backend.tooltip",
            QStringLiteral("选择读取 PE 头与可执行节的后端；HVM 必须使用私有窗口，失败不回退到 R0。")));
    m_unexplainedOnlyCheck = new QCheckBox(
        kernelText(
            "kernel.text_integrity.unexplained_only",
            QStringLiteral("只看无法解释的差异")),
        this);
    m_unexplainedOnlyCheck->setToolTip(
        kernelText(
            "kernel.text_integrity.unexplained_only.tooltip",
            QStringLiteral("勾选后隐藏归类为动态重定位的差异，只留下无法用已知机制解释的区间。")));
    m_unexplainedOnlyCheck->setChecked(true);
    m_statusLabel = new QLabel(
        kernelText(
            "kernel.text_integrity.status.idle",
            QStringLiteral("状态：点击“开始扫描”后逐模块比对可执行节")),
        this);
    m_statusLabel->setStyleSheet(
        QStringLiteral("color:%1;font-weight:600;")
            .arg(KswordTheme::TextSecondaryHex()));

    toolbar->addWidget(m_scanButton);
    toolbar->addWidget(m_cancelButton);
    toolbar->addWidget(m_backendCombo);
    toolbar->addWidget(m_moduleFilterEdit, 1);
    toolbar->addWidget(m_unexplainedOnlyCheck);
    toolbar->addWidget(m_statusLabel);
    ks::ui::NormalizeToolbarRow(toolbar);
    rootLayout->addLayout(toolbar);

    m_verdictLabel = new QLabel(this);
    m_verdictLabel->setWordWrap(true);
    m_verdictLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    m_verdictLabel->setStyleSheet(
        QStringLiteral("QLabel{padding:8px;border-radius:4px;font-weight:700;color:%1;}")
            .arg(KswordTheme::TextPrimaryHex()));
    rootLayout->addWidget(m_verdictLabel);

    auto* splitter = new QSplitter(Qt::Vertical, this);

    m_moduleTable = new ks::ui::VisibleTableWidget(splitter);
    // 模块完整性扫描结果需要留存不同扫描轮次。
    ks::ui::SetTableActionBarMode(m_moduleTable, ks::ui::TableActionBarMode::Full);
    m_moduleTable->setColumnCount(ModuleColumnCount);
    m_moduleTable->setHorizontalHeaderLabels({
        kernelText("kernel.text_integrity.module.name", QStringLiteral("模块")),
        kernelText("kernel.text_integrity.module.base", QStringLiteral("基址")),
        kernelText("kernel.text_integrity.module.backend", QStringLiteral("访问后端")),
        kernelText("kernel.text_integrity.module.sections", QStringLiteral("可执行节")),
        kernelText("kernel.text_integrity.module.scanned", QStringLiteral("已比对字节")),
        kernelText("kernel.text_integrity.module.unreadable", QStringLiteral("不可读字节")),
        kernelText("kernel.text_integrity.module.differing", QStringLiteral("差异字节")),
        kernelText("kernel.text_integrity.module.known", QStringLiteral("动态重定位位点")),
        kernelText("kernel.text_integrity.module.unexplained", QStringLiteral("无法解释")),
        kernelText("kernel.text_integrity.module.trust", QStringLiteral("磁盘信任")),
        kernelText("kernel.text_integrity.module.status", QStringLiteral("结论"))
    });
    // 归类规则跟着它解释的那一列走，比页首堆一段总说明更容易对上号。
    setHeaderTip(
        m_moduleTable,
        ModuleColumnUnreadable,
        kernelText(
            "kernel.text_integrity.module.unreadable.tooltip",
            QStringLiteral("读取失败或不完整的块只计入这里，不会被算成篡改；这些缺口阻止完整性确认。")));
    setHeaderTip(
        m_moduleTable,
        ModuleColumnKnown,
        kernelText(
            "kernel.text_integrity.module.known.tooltip",
            QStringLiteral("落在 PE 动态重定位位点上的差异（import optimization / retpoline）由加载器在启动期写入，属于正常现象。")));
    setHeaderTip(
        m_moduleTable,
        ModuleColumnUnexplained,
        kernelText(
            "kernel.text_integrity.module.unexplained.tooltip",
            QStringLiteral("无法用任何已知机制解释的差异字节数；HVCI 正在强制执行时这里非零尤其严重。")));
    m_moduleTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_moduleTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_moduleTable->setAlternatingRowColors(true);
    m_moduleTable->verticalHeader()->setVisible(false);
    m_moduleTable->horizontalHeader()->setSectionResizeMode(
        QHeaderView::ResizeToContents);
    m_moduleTable->horizontalHeader()->setStretchLastSection(true);

    m_rangeTable = new ks::ui::VisibleTableWidget(splitter);
    // 所选模块的差异区间是扫描下钻结果，保留复制导出并收拢重复快照。
    ks::ui::SetTableActionBarMode(m_rangeTable, ks::ui::TableActionBarMode::Compact);
    m_rangeTable->setColumnCount(RangeColumnCount);
    m_rangeTable->setHorizontalHeaderLabels({
        kernelText("kernel.text_integrity.range.module", QStringLiteral("模块")),
        kernelText("kernel.text_integrity.range.section", QStringLiteral("节")),
        QStringLiteral("RVA"),
        kernelText("kernel.text_integrity.range.address", QStringLiteral("内核地址")),
        kernelText("kernel.text_integrity.range.length", QStringLiteral("长度")),
        kernelText("kernel.text_integrity.range.origin", QStringLiteral("归类")),
        kernelText("kernel.text_integrity.range.clean", QStringLiteral("净映像字节")),
        kernelText("kernel.text_integrity.range.observed", QStringLiteral("内存字节"))
    });
    m_rangeTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_rangeTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_rangeTable->setAlternatingRowColors(true);
    m_rangeTable->verticalHeader()->setVisible(false);
    m_rangeTable->horizontalHeader()->setSectionResizeMode(
        QHeaderView::ResizeToContents);
    m_rangeTable->horizontalHeader()->setStretchLastSection(true);

    splitter->addWidget(m_moduleTable);
    splitter->addWidget(m_rangeTable);
    splitter->setStretchFactor(0, 2);
    splitter->setStretchFactor(1, 3);
    rootLayout->addWidget(splitter, 1);

    connect(m_scanButton, &QPushButton::clicked, this, [this]() { startScan(); });
    connect(m_cancelButton, &QPushButton::clicked, this, [this]() { cancelScan(); });
    connect(m_unexplainedOnlyCheck, &QCheckBox::toggled, this, [this](bool) {
        rebuildRangeTable();
    });
}

void KernelTextIntegrityTab::startScan()
{
    if (m_scanRunning)
    {
        return;
    }
    m_scanRunning = true;
    m_scanCancelled = false;
    m_hvciEvidenceUsable = false;
    m_hvciEnforcing = false;
    m_results.clear();
    m_moduleTable->setRowCount(0);
    m_rangeTable->setRowCount(0);
    m_scanButton->setEnabled(false);
    m_cancelButton->setEnabled(true);
    m_moduleFilterEdit->setEnabled(false);
    m_backendCombo->setEnabled(false);
    m_statusLabel->setText(
        kernelText(
            "kernel.text_integrity.status.scanning",
            QStringLiteral("状态：正在比对...")));

    m_cancelFlag = std::make_shared<std::atomic_bool>(false);
    const QString filter = m_moduleFilterEdit->text().trimmed();
    const auto backend = static_cast<ksword::memory_backend::MemoryAccessBackend>(
        m_backendCombo->currentData().toInt());
    QPointer<KernelTextIntegrityTab> safeThis(this);
    auto cancelFlag = m_cancelFlag;

    updateVerdict();
    std::thread([safeThis, filter, backend, cancelFlag]() {
        // HVCI 是否在强制执行决定了「无法解释的差异」该定成什么级别，
        // 因此在扫描线程里先取一次安全姿态。
        ksword::ark::DriverClient client;
        const auto security = client.querySecurityStatus();
        const auto hyperV = client.queryHyperVSummary();
        const bool evidenceUsable =
            security.io.ok && security.response.moduleQueryStatus >= 0;
        const bool enforcing =
            evidenceUsable
            && security.response.hvciKmciEnabled != 0U
            && security.response.hvciAuditMode == 0U
            && hyperV.io.ok
            && hyperV.response.hypervisorPresent
                == KSWORD_ARK_SECURITY_AUDIT_STATE_PRESENT
            && (security.response.secureKernelModuleLoaded
                    == KSWORD_ARK_SECURITY_AUDIT_STATE_PRESENT
                || security.response.skciModuleLoaded
                    == KSWORD_ARK_SECURITY_AUDIT_STATE_PRESENT);
        if (safeThis != nullptr)
        {
            QMetaObject::invokeMethod(
                safeThis,
                [safeThis, evidenceUsable, enforcing]() {
                    if (safeThis != nullptr)
                    {
                        safeThis->m_hvciEvidenceUsable = evidenceUsable;
                        safeThis->m_hvciEnforcing = enforcing;
                    }
                },
                Qt::QueuedConnection);
        }

        KernelTextScanOptions options;
        options.backend = backend;
        options.moduleFilter = filter;
        options.cancelFlag = cancelFlag.get();
        options.onModuleComplete =
            [safeThis](const KernelTextIntegrityResult& result) {
                if (safeThis == nullptr)
                {
                    return;
                }
                QMetaObject::invokeMethod(
                    safeThis,
                    [safeThis, result]() {
                        if (safeThis != nullptr)
                        {
                            safeThis->appendModuleResult(result);
                        }
                    },
                    Qt::QueuedConnection);
            };
        KernelCleanImageBaseline::scanExecutableSections(options);

        const bool cancelled = cancelFlag->load();
        if (safeThis == nullptr)
        {
            return;
        }
        QMetaObject::invokeMethod(
            safeThis,
            [safeThis, cancelled]() {
                if (safeThis != nullptr)
                {
                    safeThis->finishScan(cancelled);
                }
            },
            Qt::QueuedConnection);
    }).detach();
}

void KernelTextIntegrityTab::cancelScan()
{
    if (m_cancelFlag != nullptr)
    {
        m_cancelFlag->store(true);
    }
    m_cancelButton->setEnabled(false);
    m_statusLabel->setText(
        kernelText(
            "kernel.text_integrity.status.cancelling",
            QStringLiteral("状态：正在取消...")));
}

void KernelTextIntegrityTab::appendModuleResult(
    const KernelTextIntegrityResult& result)
{
    m_results.push_back(result);

    const int row = m_moduleTable->rowCount();
    m_moduleTable->insertRow(row);
    m_moduleTable->setItem(row, ModuleColumnName, readOnlyItem(result.moduleName));
    m_moduleTable->setItem(row, ModuleColumnBase, readOnlyItem(hex64(result.moduleBase)));
    m_moduleTable->setItem(
        row,
        ModuleColumnBackend,
        readOnlyItem(ks::i18n::sourceText(
            ksword::memory_backend::backendDisplayName(result.backend))));
    m_moduleTable->setItem(
        row,
        ModuleColumnSections,
        readOnlyItem(QString::number(result.executableSectionCount)));
    m_moduleTable->setItem(
        row,
        ModuleColumnScanned,
        readOnlyItem(QString::number(result.scannedBytes)));
    m_moduleTable->setItem(
        row,
        ModuleColumnUnreadable,
        readOnlyItem(QString::number(result.unreadableBytes)));
    m_moduleTable->setItem(
        row,
        ModuleColumnDiffering,
        readOnlyItem(QString::number(result.differingBytes)));
    m_moduleTable->setItem(
        row,
        ModuleColumnKnown,
        readOnlyItem(QString::number(result.knownRangeCount)));

    auto* unexplainedItem =
        readOnlyItem(QString::number(result.unexplainedRangeCount));
    unexplainedItem->setForeground(
        result.unexplainedRangeCount == 0U
            ? (result.complete ? KswordTheme::SuccessColor() : KswordTheme::WarningColor())
            : KswordTheme::ErrorColor());
    m_moduleTable->setItem(row, ModuleColumnUnexplained, unexplainedItem);

    m_moduleTable->setItem(
        row,
        ModuleColumnTrust,
        readOnlyItem(
            result.diskTrustVerified
                ? kernelText("kernel.text_integrity.trust.verified", QStringLiteral("已验证"))
                : kernelText("kernel.text_integrity.trust.unverified", QStringLiteral("未验证"))));
    m_moduleTable->setItem(
        row,
        ModuleColumnStatus,
        readOnlyItem(ks::i18n::sourceText(result.statusText)));

    // 扫描过程中持续刷新差异表与总体结论，避免长时间没有任何反馈。
    rebuildRangeTable();
    updateVerdict();
    m_statusLabel->setText(
        kernelText(
            "kernel.text_integrity.status.progress",
            QStringLiteral("状态：已比对 %1 个模块"))
            .arg(m_results.size()));
}

void KernelTextIntegrityTab::finishScan(const bool cancelled)
{
    m_scanRunning = false;
    m_scanCancelled = cancelled;
    m_scanButton->setEnabled(true);
    m_cancelButton->setEnabled(false);
    m_moduleFilterEdit->setEnabled(true);
    m_backendCombo->setEnabled(true);
    m_cancelFlag.reset();
    m_statusLabel->setText(
        cancelled
            ? kernelText(
                "kernel.text_integrity.status.cancelled",
                QStringLiteral("状态：已取消，共比对 %1 个模块"))
                .arg(m_results.size())
            : kernelText(
                "kernel.text_integrity.status.done",
                QStringLiteral("状态：完成，共比对 %1 个模块"))
                .arg(m_results.size()));
    rebuildRangeTable();
    updateVerdict();
}

void KernelTextIntegrityTab::rebuildRangeTable()
{
    const bool unexplainedOnly = m_unexplainedOnlyCheck->isChecked();
    m_rangeTable->setRowCount(0);
    for (const KernelTextIntegrityResult& result : m_results)
    {
        for (const KernelTextDiffRange& range : result.ranges)
        {
            if (unexplainedOnly
                && range.origin != KernelTextDiffRange::Origin::Unexplained)
            {
                continue;
            }
            const int row = m_rangeTable->rowCount();
            m_rangeTable->insertRow(row);
            m_rangeTable->setItem(
                row, RangeColumnModule, readOnlyItem(result.moduleName));
            m_rangeTable->setItem(
                row, RangeColumnSection, readOnlyItem(range.sectionName));
            m_rangeTable->setItem(
                row, RangeColumnRva, readOnlyItem(hex32(range.rva)));
            m_rangeTable->setItem(
                row, RangeColumnAddress, readOnlyItem(hex64(range.kernelAddress)));
            m_rangeTable->setItem(
                row, RangeColumnLength, readOnlyItem(QString::number(range.length)));

            auto* originItem = readOnlyItem(originText(range.origin));
            originItem->setForeground(
                range.origin == KernelTextDiffRange::Origin::Unexplained
                    ? KswordTheme::ErrorColor()
                    : KswordTheme::WarningColor());
            m_rangeTable->setItem(row, RangeColumnOrigin, originItem);

            m_rangeTable->setItem(
                row, RangeColumnClean, readOnlyItem(byteText(range.cleanBytes)));
            m_rangeTable->setItem(
                row, RangeColumnObserved, readOnlyItem(byteText(range.observedBytes)));
        }
    }
    m_rangeTable->resizeColumnsToContents();
}

void KernelTextIntegrityTab::updateVerdict()
{
    std::uint32_t unexplained = 0U;
    std::uint32_t known = 0U;
    std::uint32_t unparsedModules = 0U;
    std::uint32_t untrustedModules = 0U;
    std::uint32_t incompleteModules = 0U;
    for (const KernelTextIntegrityResult& result : m_results)
    {
        unexplained += result.unexplainedRangeCount;
        known += result.knownRangeCount;
        if (!result.complete)
        {
            ++incompleteModules;
        }
        if (result.unparsedDynamicRelocations)
        {
            unparsedModules += 1U;
        }
        if (result.available && !result.diskTrustVerified)
        {
            untrustedModules += 1U;
        }
    }

    QString verdict;
    QString color;
    if (unexplained == 0U
        && (m_scanRunning || m_scanCancelled || m_results.empty()
            || incompleteModules != 0U))
    {
        verdict = kernelText(
            "kernel.text_integrity.verdict.incomplete",
            QStringLiteral("扫描覆盖尚不完整，无法确认整体代码完整性（动态重定位位点差异 %1 处）"))
            .arg(known);
        color = KswordTheme::WarningHex();
    }
    else if (unexplained == 0U)
    {
        verdict = kernelText(
            "kernel.text_integrity.verdict.clean",
            QStringLiteral("未发现无法解释的代码改写（动态重定位位点差异 %1 处）"))
            .arg(known);
        color = KswordTheme::SuccessHex();
    }
    else if (m_hvciEvidenceUsable && m_hvciEnforcing)
    {
        verdict = kernelText(
            "kernel.text_integrity.verdict.hvci_violation",
            QStringLiteral("高危：HVCI 正在强制执行，内核代码页本不应可写，却发现 %1 处无法解释的改写"))
            .arg(unexplained);
        color = KswordTheme::ErrorHex();
    }
    else
    {
        verdict = kernelText(
            "kernel.text_integrity.verdict.unexplained",
            QStringLiteral("发现 %1 处无法解释的代码改写；当前未确认 HVCI 处于强制执行状态"))
            .arg(unexplained);
        color = KswordTheme::ErrorHex();
    }

    QStringList notes;
    if (incompleteModules != 0U)
    {
        notes.push_back(
            kernelText(
                "kernel.text_integrity.note.incomplete",
                QStringLiteral("%1 个模块未完成完整比对，请查看不可读字节与模块结论"))
                .arg(incompleteModules));
    }
    if (unparsedModules != 0U)
    {
        notes.push_back(
            kernelText(
                "kernel.text_integrity.note.unparsed",
                QStringLiteral("%1 个模块含本工具未解析的动态重定位符号，其「无法解释」计数偏保守"))
                .arg(unparsedModules));
    }
    if (untrustedModules != 0U)
    {
        notes.push_back(
            kernelText(
                "kernel.text_integrity.note.untrusted",
                QStringLiteral("%1 个模块的磁盘映像未通过信任校验，比对基准本身可疑"))
                .arg(untrustedModules));
    }
    if (!notes.isEmpty())
    {
        verdict += QStringLiteral("；") + notes.join(QStringLiteral("；"));
    }

    m_verdictLabel->setText(verdict);
    m_verdictLabel->setStyleSheet(
        QStringLiteral("QLabel{padding:8px;border-radius:4px;font-weight:700;color:%1;}")
            .arg(color));
}

QString KernelTextIntegrityTab::originText(const KernelTextDiffRange::Origin origin)
{
    return origin == KernelTextDiffRange::Origin::KnownDynamicRelocation
        ? kernelText(
            "kernel.text_integrity.origin.dynamic",
            QStringLiteral("动态重定位位点"))
        : kernelText(
            "kernel.text_integrity.origin.unexplained",
            QStringLiteral("无法解释"));
}

QString KernelTextIntegrityTab::byteText(const std::vector<std::uint8_t>& bytes)
{
    QStringList parts;
    parts.reserve(static_cast<qsizetype>(bytes.size()));
    for (const std::uint8_t value : bytes)
    {
        parts.push_back(
            QStringLiteral("%1").arg(value, 2, 16, QLatin1Char('0')).toUpper());
    }
    return parts.join(QLatin1Char(' '));
}

QString KernelTextIntegrityTab::hex64(const std::uint64_t value)
{
    return QStringLiteral("0x%1")
        .arg(value, 16, 16, QLatin1Char('0'));
}

QString KernelTextIntegrityTab::hex32(const std::uint32_t value)
{
    return QStringLiteral("0x%1")
        .arg(value, 8, 16, QLatin1Char('0'));
}
