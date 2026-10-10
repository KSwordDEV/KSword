#include "KernelVbsPostureTab.h"
#include "../UI/PageControlStyle.h"
#include "../UI/ToolbarMetrics.h"

#include "KernelDock.h"
#include "../ArkDriverClient/ArkDriverClient.h"
#include "../UI/VisibleTableWidget.h"
#include "../theme.h"

#include <QAbstractItemView>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QLabel>
#include <QList>
#include <QMetaObject>
#include <QPointer>
#include <QPushButton>
#include <QShowEvent>
#include <QSplitter>
#include <QStringList>
#include <QTableWidget>
#include <QTableWidgetItem>
#include "../UI/StructuredFieldView.h"
#include <QVBoxLayout>

#include <thread>
#include <utility>

using ksword::kernel_dock_internal::kernelText;

namespace
{
    enum PostureColumn : int
    {
        PostureColumnItem = 0,
        PostureColumnObserved,
        PostureColumnVerdict,
        PostureColumnSource,
        PostureColumnCount
    };

    QTableWidgetItem* readOnlyItem(const QString& text)
    {
        auto* item = new QTableWidgetItem(text);
        item->setFlags(item->flags() & ~Qt::ItemIsEditable);
        return item;
    }

    QString hex32(const std::uint32_t value)
    {
        return QStringLiteral("0x%1").arg(value, 8, 16, QLatin1Char('0')).toUpper().replace(
            QStringLiteral("0X"), QStringLiteral("0x"));
    }

    // 模块以 PRESENT 状态出现才算真的加载；UNKNOWN/UNAVAILABLE 只代表证据缺失。
    bool modulePresent(const std::uint32_t state)
    {
        return state == KSWORD_ARK_SECURITY_AUDIT_STATE_PRESENT;
    }
}

KernelVbsPostureTab::KernelVbsPostureTab(QWidget* parent)
    : QWidget(parent)
{
    initializeUi();
}

void KernelVbsPostureTab::showEvent(QShowEvent* event)
{
    QWidget::showEvent(event);
    if (!m_firstRefreshStarted)
    {
        m_firstRefreshStarted = true;
        QMetaObject::invokeMethod(
            this,
            [this]() { refreshAsync(); },
            Qt::QueuedConnection);
    }
}

void KernelVbsPostureTab::initializeUi()
{
    auto* rootLayout = new QVBoxLayout(this);
    rootLayout->setContentsMargins(6, 6, 6, 6);
    rootLayout->setSpacing(6);

    auto* toolbar = new QHBoxLayout();
    m_refreshButton = new QPushButton(
        kernelText("kernel.vbs_posture.refresh", QStringLiteral("刷新姿态")),
        this);
    // 判定口径不占版面：挂在触发采集的按钮上，谁要看谁悬停。
    m_refreshButton->setToolTip(
        kernelText(
            "kernel.vbs_posture.refresh.tooltip",
            QStringLiteral("策略位只说明「配置想开」，HVCI 真正生效还需要 hypervisor 在位且 securekernel.exe / skci.dll 已加载。")));
    m_refreshButton->setStyleSheet(KswordTheme::ThemedButtonStyle());
    m_statusLabel = new QLabel(
        kernelText("kernel.vbs_posture.status.waiting", QStringLiteral("状态：等待刷新")),
        this);
    m_statusLabel->setStyleSheet(
        QStringLiteral("color:%1;font-weight:600;").arg(KswordTheme::TextSecondaryHex()));
    toolbar->addWidget(m_refreshButton);
    toolbar->addStretch(1);
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

    m_downgradeLabel = new QLabel(this);
    m_downgradeLabel->setWordWrap(true);
    m_downgradeLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    m_downgradeLabel->setStyleSheet(
        QStringLiteral("QLabel{padding:6px;color:%1;}").arg(KswordTheme::TextPrimaryHex()));
    rootLayout->addWidget(m_downgradeLabel);

    auto* splitter = new QSplitter(Qt::Vertical, this);

    m_table = new ks::ui::VisibleTableWidget(splitter);
    // 少量安全姿态检查项已有详细报告，不需要重复快照/冻结栏。
    ks::ui::SetTableActionBarMode(m_table, ks::ui::TableActionBarMode::None);
    m_table->setColumnCount(PostureColumnCount);
    m_table->setHorizontalHeaderLabels({
        kernelText("kernel.vbs_posture.column.item", QStringLiteral("检查项")),
        kernelText("kernel.vbs_posture.column.observed", QStringLiteral("观测值")),
        kernelText("kernel.vbs_posture.column.verdict", QStringLiteral("判定")),
        kernelText("kernel.vbs_posture.column.source", QStringLiteral("证据来源"))
    });
    // 「两侧证据不一致按未启用处理」这条规则跟着它解释的那一列走。
    QTableWidgetItem* verdictHeader = m_table->horizontalHeaderItem(PostureColumnVerdict);
    if (verdictHeader != nullptr)
    {
        verdictHeader->setToolTip(
            kernelText(
                "kernel.vbs_posture.column.verdict.tooltip",
                QStringLiteral("策略位与运行证据不一致时一律按未启用处理，不会因为策略位为 1 就判定为已启用。")));
    }
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_table->setAlternatingRowColors(true);
    m_table->verticalHeader()->setVisible(false);
    m_table->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    m_table->horizontalHeader()->setStretchLastSection(true);

    m_detailEdit = new ks::ui::StructuredFieldView(splitter);

    m_detailEdit->setDocument(ks::ui::FieldDocument{}.note(
        kernelText(
            "kernel.vbs_posture.detail.placeholder",
            QStringLiteral("刷新后显示 CodeIntegrity 选项掩码、Hyper-V 模块状态与原始 NTSTATUS"))));

    splitter->addWidget(m_table);
    splitter->addWidget(m_detailEdit);
    splitter->setStretchFactor(0, 3);
    splitter->setStretchFactor(1, 2);
    rootLayout->addWidget(splitter, 1);

    connect(m_refreshButton, &QPushButton::clicked, this, [this]() { refreshAsync(); });
}

void KernelVbsPostureTab::refreshAsync()
{
    if (m_queryRunning)
    {
        return;
    }
    m_queryRunning = true;
    m_refreshButton->setEnabled(false);
    m_statusLabel->setText(
        kernelText(
            "kernel.vbs_posture.status.refreshing",
            QStringLiteral("状态：正在采集只读安全姿态...")));

    QPointer<KernelVbsPostureTab> safeThis(this);
    std::thread([safeThis]() {
        ksword::ark::DriverClient client;
        Snapshot snapshot;
        snapshot.security = client.querySecurityStatus();
        snapshot.hyperV = client.queryHyperVSummary();
        if (safeThis == nullptr)
        {
            return;
        }
        QMetaObject::invokeMethod(
            safeThis,
            [safeThis, snapshot = std::move(snapshot)]() mutable {
                if (safeThis != nullptr)
                {
                    safeThis->applySnapshot(std::move(snapshot));
                }
            },
            Qt::QueuedConnection);
    }).detach();
}

void KernelVbsPostureTab::applySnapshot(Snapshot snapshot)
{
    m_queryRunning = false;
    m_refreshButton->setEnabled(true);

    if (!snapshot.security.io.ok)
    {
        m_table->setRowCount(0);
        m_detailEdit->setDocument({});
        m_downgradeLabel->clear();
        const QString failureText = snapshot.security.unsupported
            ? kernelText(
                "kernel.vbs_posture.status.unsupported",
                QStringLiteral("状态：当前驱动不支持安全姿态审计协议"))
            : kernelText(
                "kernel.vbs_posture.status.failed",
                QStringLiteral("状态：读取失败（%1）"))
                .arg(QString::fromStdString(snapshot.security.io.message));
        m_statusLabel->setText(failureText);
        m_verdictLabel->setText(failureText);
        m_verdictLabel->setStyleSheet(
            QStringLiteral("QLabel{padding:8px;border-radius:4px;font-weight:700;color:%1;}")
                .arg(KswordTheme::ErrorHex()));
        return;
    }

    const QList<PostureRow> rows = buildRows(snapshot);
    populateTable(rows);
    applyVerdictBanner(snapshot, rows);
    m_detailEdit->setDocument(buildDetail(snapshot));
    m_statusLabel->setText(
        snapshot.security.response.queryStatus < 0
            ? kernelText(
                "kernel.vbs_posture.status.partial",
                QStringLiteral("状态：部分证据不可用（%1）"))
                .arg(ntStatusText(snapshot.security.response.queryStatus))
            : kernelText("kernel.vbs_posture.status.ready", QStringLiteral("状态：已刷新")));
}

QList<KernelVbsPostureTab::PostureRow> KernelVbsPostureTab::buildRows(const Snapshot& snapshot)
{
    const auto& security = snapshot.security.response;
    const bool hyperVOk = snapshot.hyperV.io.ok;
    const auto& hyperV = snapshot.hyperV.response;

    const QString sourceCi = QStringLiteral("SystemCodeIntegrityInformation");
    const QString sourceModule = kernelText(
        "kernel.vbs_posture.source.module", QStringLiteral("已加载模块快照"));
    const QString sourceCpuid = QStringLiteral("CPUID");

    QList<PostureRow> rows;

    // 第一组：策略意图。
    rows.append({
        kernelText("kernel.vbs_posture.item.kmci_policy", QStringLiteral("HVCI/KMCI 策略位")),
        boolText(security.hvciKmciEnabled),
        security.hvciKmciEnabled != 0U
            ? kernelText("kernel.vbs_posture.verdict.policy_on", QStringLiteral("策略要求启用"))
            : kernelText("kernel.vbs_posture.verdict.policy_off", QStringLiteral("策略未启用")),
        sourceCi,
        security.hvciKmciEnabled != 0U ? Severity::Good : Severity::Bad,
        false
    });
    rows.append({
        kernelText("kernel.vbs_posture.item.kmci_audit", QStringLiteral("HVCI/KMCI 审计模式")),
        boolText(security.hvciAuditMode),
        security.hvciAuditMode != 0U
            ? kernelText("kernel.vbs_posture.verdict.audit_only", QStringLiteral("只记录不阻断，等同未强制"))
            : kernelText("kernel.vbs_posture.verdict.enforcing", QStringLiteral("非审计模式")),
        sourceCi,
        security.hvciAuditMode != 0U ? Severity::Bad : Severity::Good,
        security.hvciAuditMode != 0U
    });
    rows.append({
        kernelText("kernel.vbs_posture.item.kmci_strict", QStringLiteral("HVCI/KMCI 严格模式")),
        boolText(security.hvciStrictMode),
        security.hvciStrictMode != 0U
            ? kernelText("kernel.vbs_posture.verdict.strict_on", QStringLiteral("严格模式已开"))
            : kernelText("kernel.vbs_posture.verdict.strict_off", QStringLiteral("未开启严格模式")),
        sourceCi,
        security.hvciStrictMode != 0U ? Severity::Good : Severity::Neutral,
        false
    });
    rows.append({
        kernelText("kernel.vbs_posture.item.ium", QStringLiteral("IUM（隔离用户模式）签名")),
        boolText(security.hvciIumEnabled),
        security.hvciIumEnabled != 0U
            ? kernelText("kernel.vbs_posture.verdict.ium_on", QStringLiteral("已启用"))
            : kernelText("kernel.vbs_posture.verdict.ium_off", QStringLiteral("未启用")),
        sourceCi,
        security.hvciIumEnabled != 0U ? Severity::Good : Severity::Neutral,
        false
    });

    // 第二组：运行时证据。策略位为真但这一组缺失，就是「以为开着其实没开」。
    rows.append({
        kernelText("kernel.vbs_posture.item.hypervisor", QStringLiteral("Hypervisor 在位")),
        hyperVOk
            ? QStringLiteral("%1 %2")
                .arg(moduleStateText(hyperV.hypervisorPresent))
                .arg(fixedWide(hyperV.hypervisorVendor, sizeof(hyperV.hypervisorVendor) / sizeof(wchar_t)))
                .trimmed()
            : moduleStateText(KSWORD_ARK_SECURITY_AUDIT_STATE_UNAVAILABLE),
        (hyperVOk && modulePresent(hyperV.hypervisorPresent))
            ? kernelText("kernel.vbs_posture.verdict.hv_present", QStringLiteral("CPUID 报告 hypervisor 存在"))
            : kernelText("kernel.vbs_posture.verdict.hv_absent", QStringLiteral("未观测到 hypervisor")),
        sourceCpuid,
        (hyperVOk && modulePresent(hyperV.hypervisorPresent)) ? Severity::Good : Severity::Bad,
        false
    });
    rows.append({
        QStringLiteral("securekernel.exe"),
        moduleStateText(security.secureKernelModuleLoaded),
        modulePresent(security.secureKernelModuleLoaded)
            ? kernelText("kernel.vbs_posture.verdict.sk_loaded", QStringLiteral("安全内核已加载"))
            : kernelText("kernel.vbs_posture.verdict.sk_missing", QStringLiteral("未观测到安全内核")),
        sourceModule,
        modulePresent(security.secureKernelModuleLoaded) ? Severity::Good : Severity::Bad,
        false
    });
    rows.append({
        QStringLiteral("skci.dll"),
        moduleStateText(security.skciModuleLoaded),
        modulePresent(security.skciModuleLoaded)
            ? kernelText("kernel.vbs_posture.verdict.skci_loaded", QStringLiteral("VTL1 代码完整性模块已加载"))
            : kernelText("kernel.vbs_posture.verdict.skci_missing", QStringLiteral("未观测到 skci")),
        sourceModule,
        modulePresent(security.skciModuleLoaded) ? Severity::Good : Severity::Bad,
        false
    });
    rows.append({
        QStringLiteral("ci.dll"),
        moduleStateText(security.ciModuleLoaded),
        modulePresent(security.ciModuleLoaded)
            ? kernelText("kernel.vbs_posture.verdict.ci_loaded", QStringLiteral("VTL0 代码完整性模块已加载"))
            : kernelText("kernel.vbs_posture.verdict.ci_missing", QStringLiteral("未观测到 ci")),
        sourceModule,
        modulePresent(security.ciModuleLoaded) ? Severity::Good : Severity::Warning,
        false
    });
    rows.append({
        kernelText("kernel.vbs_posture.item.vbs_derived", QStringLiteral("VBS 存在（派生值）")),
        boolText(security.vbsPresent),
        kernelText(
            "kernel.vbs_posture.verdict.vbs_derived",
            QStringLiteral("由策略位与模块状态推导，不作为独立运行证据")),
        sourceModule,
        Severity::Neutral,
        false
    });

    // 第三组：会削弱内核代码完整性的降级项。
    rows.append({
        kernelText("kernel.vbs_posture.item.ci_enabled", QStringLiteral("内核 CI 启用")),
        boolText(security.ciEnabled),
        security.ciEnabled != 0U
            ? kernelText("kernel.vbs_posture.verdict.ci_on", QStringLiteral("已启用"))
            : kernelText("kernel.vbs_posture.verdict.ci_off", QStringLiteral("未启用")),
        sourceCi,
        security.ciEnabled != 0U ? Severity::Good : Severity::Bad,
        security.ciEnabled == 0U
    });
    rows.append({
        kernelText("kernel.vbs_posture.item.testsigning", QStringLiteral("测试签名模式")),
        boolText(security.testSigningEnabled),
        security.testSigningEnabled != 0U
            ? kernelText("kernel.vbs_posture.verdict.testsign_on", QStringLiteral("允许加载测试签名驱动"))
            : kernelText("kernel.vbs_posture.verdict.testsign_off", QStringLiteral("未开启")),
        sourceCi,
        security.testSigningEnabled != 0U ? Severity::Bad : Severity::Good,
        security.testSigningEnabled != 0U
    });
    rows.append({
        kernelText("kernel.vbs_posture.item.ci_debug", QStringLiteral("CI 调试模式")),
        boolText(security.ciDebugModeEnabled),
        security.ciDebugModeEnabled != 0U
            ? kernelText("kernel.vbs_posture.verdict.ci_debug_on", QStringLiteral("代码完整性策略被放宽"))
            : kernelText("kernel.vbs_posture.verdict.ci_debug_off", QStringLiteral("未开启")),
        sourceCi,
        security.ciDebugModeEnabled != 0U ? Severity::Bad : Severity::Good,
        security.ciDebugModeEnabled != 0U
    });
    rows.append({
        kernelText("kernel.vbs_posture.item.kd", QStringLiteral("内核调试器")),
        boolText(security.kernelDebuggerEnabled),
        security.kernelDebuggerEnabled != 0U
            ? kernelText("kernel.vbs_posture.verdict.kd_on", QStringLiteral("已连接或已启用"))
            : kernelText("kernel.vbs_posture.verdict.kd_off", QStringLiteral("未启用")),
        kernelText("kernel.vbs_posture.source.kd", QStringLiteral("KdDebuggerEnabled")),
        security.kernelDebuggerEnabled != 0U ? Severity::Warning : Severity::Good,
        security.kernelDebuggerEnabled != 0U
    });
    rows.append({
        kernelText("kernel.vbs_posture.item.secure_boot", QStringLiteral("Secure Boot")),
        QStringLiteral("%1 / %2")
            .arg(boolText(security.secureBootEnabled))
            .arg(boolText(security.secureBootCapable)),
        security.secureBootEnabled != 0U
            ? kernelText("kernel.vbs_posture.verdict.sb_on", QStringLiteral("已启用"))
            : kernelText("kernel.vbs_posture.verdict.sb_off", QStringLiteral("未启用（VBS 的信任根被削弱）")),
        kernelText("kernel.vbs_posture.source.secure_boot", QStringLiteral("SystemSecureBootInformation")),
        security.secureBootEnabled != 0U ? Severity::Good : Severity::Warning,
        security.secureBootEnabled == 0U
    });
    rows.append({
        kernelText("kernel.vbs_posture.item.build_flags", QStringLiteral("测试/预览版构建")),
        QStringLiteral("test=%1 flight=%2 flighting=%3")
            .arg(boolText(security.testBuild))
            .arg(boolText(security.flightBuild))
            .arg(boolText(security.flightingEnabled)),
        (security.testBuild != 0U || security.flightBuild != 0U)
            ? kernelText("kernel.vbs_posture.verdict.build_relaxed", QStringLiteral("非零售构建，签名策略可能不同"))
            : kernelText("kernel.vbs_posture.verdict.build_retail", QStringLiteral("零售构建")),
        sourceCi,
        (security.testBuild != 0U || security.flightBuild != 0U) ? Severity::Warning : Severity::Good,
        false
    });

    return rows;
}

void KernelVbsPostureTab::populateTable(const QList<PostureRow>& rows)
{
    m_table->setRowCount(0);
    for (const PostureRow& row : rows)
    {
        const int tableRow = m_table->rowCount();
        m_table->insertRow(tableRow);
        m_table->setItem(tableRow, PostureColumnItem, readOnlyItem(row.item));
        m_table->setItem(tableRow, PostureColumnObserved, readOnlyItem(row.observed));

        auto* verdictItem = readOnlyItem(row.verdict);
        switch (row.severity)
        {
        case Severity::Good:
            verdictItem->setForeground(KswordTheme::SuccessColor());
            break;
        case Severity::Warning:
            verdictItem->setForeground(KswordTheme::WarningColor());
            break;
        case Severity::Bad:
            verdictItem->setForeground(KswordTheme::ErrorColor());
            break;
        case Severity::Neutral:
        default:
            break;
        }
        m_table->setItem(tableRow, PostureColumnVerdict, verdictItem);
        m_table->setItem(tableRow, PostureColumnSource, readOnlyItem(row.source));
    }
    m_table->resizeColumnsToContents();
}

void KernelVbsPostureTab::applyVerdictBanner(
    const Snapshot& snapshot,
    const QList<PostureRow>& rows)
{
    const auto& security = snapshot.security.response;
    const bool policyEnabled = security.hvciKmciEnabled != 0U;
    const bool auditMode = security.hvciAuditMode != 0U;

    // 运行证据必须来自与策略位无关的观测：hypervisor 在位 + VTL1 模块已加载。
    const bool hypervisorPresent = snapshot.hyperV.io.ok
        && modulePresent(snapshot.hyperV.response.hypervisorPresent);
    const bool vtl1Present = modulePresent(security.secureKernelModuleLoaded)
        || modulePresent(security.skciModuleLoaded);
    const bool moduleEvidenceUsable = security.moduleQueryStatus >= 0;
    const bool running = hypervisorPresent && vtl1Present;

    QString verdict;
    QString color;
    if (!moduleEvidenceUsable)
    {
        verdict = kernelText(
            "kernel.vbs_posture.verdict.no_evidence",
            QStringLiteral("证据不足：模块快照查询失败（%1），无法判定 HVCI 是否真正运行"))
            .arg(ntStatusText(security.moduleQueryStatus));
        color = KswordTheme::WarningHex();
    }
    else if (policyEnabled && running && auditMode)
    {
        verdict = kernelText(
            "kernel.vbs_posture.verdict.running_audit",
            QStringLiteral("HVCI 运行中，但处于审计模式：违规只被记录，不会被阻断"));
        color = KswordTheme::WarningHex();
    }
    else if (policyEnabled && running)
    {
        verdict = kernelText(
            "kernel.vbs_posture.verdict.running",
            QStringLiteral("HVCI 正在强制执行：策略位与运行时证据一致"));
        color = KswordTheme::SuccessHex();
    }
    else if (policyEnabled && !running)
    {
        verdict = kernelText(
            "kernel.vbs_posture.verdict.policy_only",
            QStringLiteral("策略声称已启用，但缺少运行证据（hypervisor 或 securekernel/skci 未观测到）——按未启用处理"));
        color = KswordTheme::ErrorHex();
    }
    else if (!policyEnabled && running)
    {
        verdict = kernelText(
            "kernel.vbs_posture.verdict.vbs_only",
            QStringLiteral("VBS 在运行，但 KMCI 策略位未启用：内核代码完整性未受 VTL1 强制"));
        color = KswordTheme::ErrorHex();
    }
    else
    {
        verdict = kernelText(
            "kernel.vbs_posture.verdict.disabled",
            QStringLiteral("HVCI 未启用：内核代码页不受 VTL1 强制保护"));
        color = KswordTheme::ErrorHex();
    }

    m_verdictLabel->setText(verdict);
    m_verdictLabel->setStyleSheet(
        QStringLiteral("QLabel{padding:8px;border-radius:4px;font-weight:700;color:%1;}")
            .arg(color));

    QStringList downgrades;
    for (const PostureRow& row : rows)
    {
        if (row.downgrade)
        {
            downgrades.push_back(row.item);
        }
    }
    m_downgradeLabel->setText(
        downgrades.isEmpty()
            ? kernelText(
                "kernel.vbs_posture.downgrade.none",
                QStringLiteral("降级项：未发现"))
            : kernelText(
                "kernel.vbs_posture.downgrade.list",
                QStringLiteral("降级项（%1）：%2"))
                .arg(downgrades.size())
                .arg(downgrades.join(QStringLiteral("、"))));
}

ks::ui::FieldDocument KernelVbsPostureTab::buildDetail(const Snapshot& snapshot)
{
    const auto& security = snapshot.security.response;
    ks::ui::FieldDocument lines;

    lines.section(QStringLiteral("SystemCodeIntegrityInformation"));
    lines.field(QStringLiteral("codeIntegrityOptions"), QStringLiteral("%1").arg(hex32(security.codeIntegrityOptions)));
    lines.note(QStringLiteral("%1").arg(codeIntegrityOptionText(security.codeIntegrityOptions)));
    lines.field(QStringLiteral("fieldFlags"), QStringLiteral("%1").arg(hex32(security.fieldFlags)));
    lines.field(QStringLiteral("sourceMask"), QStringLiteral("%1").arg(hex32(security.sourceMask)));
    lines.field(QStringLiteral("queryStatus"), QStringLiteral("%1").arg(ntStatusText(security.queryStatus)));
    lines.field(QStringLiteral("codeIntegrityStatus"), QStringLiteral("%1").arg(ntStatusText(security.codeIntegrityStatus)));
    lines.field(QStringLiteral("secureBootStatus"), QStringLiteral("%1").arg(ntStatusText(security.secureBootStatus)));
    lines.field(QStringLiteral("moduleQueryStatus"), QStringLiteral("%1").arg(ntStatusText(security.moduleQueryStatus)));
    lines.field(QStringLiteral("debuggerStatus"), QStringLiteral("%1").arg(ntStatusText(security.debuggerStatus)));
    lines.field(QStringLiteral("kernelDebuggerEnabled"), QStringLiteral("%1").arg(security.kernelDebuggerEnabled));
    lines.field(QStringLiteral("kernelDebuggerNotPresent"), QStringLiteral("%1").arg(security.kernelDebuggerNotPresent));


    lines.section(QStringLiteral("Hyper-V summary"));
    if (!snapshot.hyperV.io.ok)
    {
        lines.note((snapshot.hyperV.unsupported
            ? QStringLiteral("unsupported by current driver")
            : QStringLiteral("query failed: %1")
                .arg(QString::fromStdString(snapshot.hyperV.io.message))));
    }
    else
    {
        const auto& hyperV = snapshot.hyperV.response;
        lines.field(QStringLiteral("hypervisorPresent"), QStringLiteral("%1").arg(moduleStateText(hyperV.hypervisorPresent)));
        lines.field(QStringLiteral("vendor"), QStringLiteral("%1").arg(fixedWide(hyperV.hypervisorVendor, sizeof(hyperV.hypervisorVendor) / sizeof(wchar_t))));
        lines.field(QStringLiteral("winhv.sys"), QStringLiteral("%1").arg(moduleStateText(hyperV.winHvStatus)));
        lines.field(QStringLiteral("winhvr.sys"), QStringLiteral("%1").arg(moduleStateText(hyperV.winHvRuntimeStatus)));
        lines.field(QStringLiteral("hvloader.sys"), QStringLiteral("%1").arg(moduleStateText(hyperV.hvLoaderStatus)));
        lines.field(QStringLiteral("vmbus"), QStringLiteral("%1").arg(moduleStateText(hyperV.vmbusStatus)));
        lines.field(QStringLiteral("vmswitch"), QStringLiteral("%1").arg(moduleStateText(hyperV.vSwitchStatus)));
        lines.field(QStringLiteral("vpci"), QStringLiteral("%1").arg(moduleStateText(hyperV.vPciStatus)));
        lines.field(QStringLiteral("hvsocket"), QStringLiteral("%1").arg(moduleStateText(hyperV.hvSocketStatus)));
        lines.field(QStringLiteral("rootPartitionStatus"), QStringLiteral("%1").arg(moduleStateText(hyperV.rootPartitionStatus)));
        lines.field(QStringLiteral("moduleQueryStatus"), QStringLiteral("%1").arg(ntStatusText(hyperV.moduleQueryStatus)));
    }

    return lines;
}

QString KernelVbsPostureTab::codeIntegrityOptionText(const std::uint32_t options)
{
    if (options == 0U)
    {
        return QStringLiteral("(none)");
    }
    QStringList parts;
    const struct
    {
        std::uint32_t bit;
        const char* name;
    } table[] = {
        { KSWORD_ARK_CODEINTEGRITY_OPTION_ENABLED, "ENABLED" },
        { KSWORD_ARK_CODEINTEGRITY_OPTION_TESTSIGN, "TESTSIGN" },
        { KSWORD_ARK_CODEINTEGRITY_OPTION_UMCI_ENABLED, "UMCI_ENABLED" },
        { KSWORD_ARK_CODEINTEGRITY_OPTION_UMCI_AUDITMODE_ENABLED, "UMCI_AUDITMODE" },
        { KSWORD_ARK_CODEINTEGRITY_OPTION_TEST_BUILD, "TEST_BUILD" },
        { KSWORD_ARK_CODEINTEGRITY_OPTION_DEBUGMODE_ENABLED, "DEBUGMODE" },
        { KSWORD_ARK_CODEINTEGRITY_OPTION_FLIGHT_BUILD, "FLIGHT_BUILD" },
        { KSWORD_ARK_CODEINTEGRITY_OPTION_FLIGHTING_ENABLED, "FLIGHTING" },
        { KSWORD_ARK_CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED, "HVCI_KMCI_ENABLED" },
        { KSWORD_ARK_CODEINTEGRITY_OPTION_HVCI_KMCI_AUDITMODE, "HVCI_KMCI_AUDITMODE" },
        { KSWORD_ARK_CODEINTEGRITY_OPTION_HVCI_KMCI_STRICTMODE, "HVCI_KMCI_STRICTMODE" },
        { KSWORD_ARK_CODEINTEGRITY_OPTION_HVCI_IUM_ENABLED, "HVCI_IUM_ENABLED" },
        { KSWORD_ARK_CODEINTEGRITY_OPTION_WHQL_ENFORCEMENT, "WHQL_ENFORCEMENT" },
        { KSWORD_ARK_CODEINTEGRITY_OPTION_WHQL_AUDITMODE, "WHQL_AUDITMODE" }
    };
    std::uint32_t known = 0U;
    for (const auto& entry : table)
    {
        if ((options & entry.bit) != 0U)
        {
            parts.push_back(QString::fromLatin1(entry.name));
            known |= entry.bit;
        }
    }
    const std::uint32_t leftover = options & ~known;
    if (leftover != 0U)
    {
        parts.push_back(hex32(leftover));
    }
    return parts.join(QStringLiteral(" | "));
}

QString KernelVbsPostureTab::moduleStateText(const std::uint32_t state)
{
    switch (state)
    {
    case KSWORD_ARK_SECURITY_AUDIT_STATE_PRESENT:
        return kernelText("kernel.vbs_posture.state.present", QStringLiteral("已加载"));
    case KSWORD_ARK_SECURITY_AUDIT_STATE_ABSENT:
        return kernelText("kernel.vbs_posture.state.absent", QStringLiteral("未加载"));
    case KSWORD_ARK_SECURITY_AUDIT_STATE_ENABLED:
        return kernelText("kernel.vbs_posture.state.enabled", QStringLiteral("已启用"));
    case KSWORD_ARK_SECURITY_AUDIT_STATE_DISABLED:
        return kernelText("kernel.vbs_posture.state.disabled", QStringLiteral("已禁用"));
    case KSWORD_ARK_SECURITY_AUDIT_STATE_DEGRADED:
        return kernelText("kernel.vbs_posture.state.degraded", QStringLiteral("降级"));
    case KSWORD_ARK_SECURITY_AUDIT_STATE_UNAVAILABLE:
        return kernelText("kernel.vbs_posture.state.unavailable", QStringLiteral("不可用"));
    case KSWORD_ARK_SECURITY_AUDIT_STATE_UNKNOWN:
    default:
        return kernelText("kernel.vbs_posture.state.unknown", QStringLiteral("未知"));
    }
}

QString KernelVbsPostureTab::boolText(const std::uint32_t value)
{
    return value != 0U
        ? kernelText("kernel.vbs_posture.bool.yes", QStringLiteral("是"))
        : kernelText("kernel.vbs_posture.bool.no", QStringLiteral("否"));
}

QString KernelVbsPostureTab::ntStatusText(const long status)
{
    return QStringLiteral("0x%1")
        .arg(static_cast<unsigned long>(status), 8, 16, QLatin1Char('0'));
}

QString KernelVbsPostureTab::fixedWide(const wchar_t* text, const std::size_t capacity)
{
    if (text == nullptr || capacity == 0U)
    {
        return QString();
    }
    std::size_t length = 0U;
    while (length < capacity && text[length] != L'\0')
    {
        ++length;
    }
    return QString::fromWCharArray(text, static_cast<int>(length));
}
