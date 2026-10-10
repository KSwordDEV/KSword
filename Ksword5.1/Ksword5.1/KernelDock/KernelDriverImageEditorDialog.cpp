#include "KernelDriverImageEditorDialog.h"
#include "../UI/SecondaryPageLayout.h"
#include "../UI/ToolbarMetrics.h"
#include "../UI/VisibleTableWidget.h"

#include "KernelDock.h"
#include "../ArkDriverClient/ArkDriverClient.h"
#include "../UI/StructuredFieldView.h"
#include "../theme.h"

#include <QAbstractItemView>
#include <QCheckBox>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QIcon>
#include <QInputDialog>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPushButton>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTimer>
#include <QVBoxLayout>

#include <iterator>
#include <limits>

using ksword::kernel_dock_internal::kernelText;

namespace
{
    enum Column : int
    {
        ColumnSelected = 0,
        ColumnField,
        ColumnCurrent,
        ColumnDesired,
        ColumnState,
        ColumnOriginal,
        ColumnApplied,
        ColumnCount
    };

    struct FieldRowSpec
    {
        std::uint32_t mask;
        const char* translationKey;
        const char* fallbackText;
        bool naturalUlong;
    };

    constexpr FieldRowSpec FieldRows[] = {
        { KSWORD_ARK_DRIVER_IMAGE_FIELD_DRIVER_START,
          "kernel.driver_image.field.driver_start",
          "DriverObject->DriverStart", false },
        { KSWORD_ARK_DRIVER_IMAGE_FIELD_DRIVER_SIZE,
          "kernel.driver_image.field.driver_size",
          "DriverObject->DriverSize", true },
        { KSWORD_ARK_DRIVER_IMAGE_FIELD_DRIVER_SECTION,
          "kernel.driver_image.field.driver_section",
          "DriverObject->DriverSection", false },
        { KSWORD_ARK_DRIVER_IMAGE_FIELD_KLDR_DLL_BASE,
          "kernel.driver_image.field.kldr_dll_base",
          "KLDR_DATA_TABLE_ENTRY.DllBase", false },
        { KSWORD_ARK_DRIVER_IMAGE_FIELD_KLDR_SIZE_OF_IMAGE,
          "kernel.driver_image.field.kldr_size",
          "KLDR_DATA_TABLE_ENTRY.SizeOfImage", true },
    };

    QTableWidgetItem* readOnlyItem(const QString& text)
    {
        auto* item = new QTableWidgetItem(text);
        item->setFlags(item->flags() & ~Qt::ItemIsEditable);
        return item;
    }

    QTableWidgetItem* selectionItem()
    {
        auto* item = new QTableWidgetItem();
        item->setFlags(
            (item->flags() | Qt::ItemIsUserCheckable) &
            ~Qt::ItemIsEditable);
        item->setCheckState(Qt::Checked);
        return item;
    }

    QString ioMessageText(const std::string& text)
    {
        return QString::fromUtf8(
            text.c_str(),
            static_cast<int>(text.size()));
    }

    QString maskText(const std::uint32_t value)
    {
        return QStringLiteral("0x%1")
            .arg(value, 8, 16, QChar('0'))
            .toUpper();
    }
}

KernelDriverImageEditorDialog::KernelDriverImageEditorDialog(
    const QString& driverObjectName,
    QWidget* parent)
    : QDialog(parent),
      m_requestedDriverName(driverObjectName.trimmed())
{
    initializeUi();
    QTimer::singleShot(0, this, [this]() { refreshSnapshot(); });
}

// 构建明确不透明的高级编辑器；每个可执行按钮都有图标和后果说明。
void KernelDriverImageEditorDialog::initializeUi()
{
    setObjectName(QStringLiteral("kernelDriverImageEditorDialog"));
    setWindowTitle(kernelText(
        "kernel.driver_image.title",
        QStringLiteral("DriverObject / KLDR 镜像事务编辑器")));
    resize(1240, 860);
    setModal(true);
    setStyleSheet(KswordTheme::OpaqueDialogStyle(objectName()));
    ks::ui::StyleSecondaryWindow(this);

    auto* rootLayout = new QVBoxLayout(this);
    ks::ui::StyleSecondaryContentLayout(rootLayout);

    m_riskLabel = new QLabel(
        kernelText(
            "kernel.driver_image.risk",
            QStringLiteral("极高风险：本页允许任意修改 DriverStart、DriverSize、DriverSection、KLDR DllBase/SizeOfImage，并可把任意驱动从 PsLoadedModuleList 摘链或重新插入。错误值可能立即蓝屏、破坏 I/O、触发 PatchGuard、损坏崩溃转储/符号解析，或使恢复记录永久失效；这里只告知风险，不按驱动类别或值限制操作。")),
        this);
    m_riskLabel->setWordWrap(true);
    m_riskLabel->setStyleSheet(
        QStringLiteral(
            "color:%1;background:%2;font-weight:700;"
            "border:1px solid %1;padding:8px;")
            .arg(KswordTheme::ErrorHex())
            .arg(KswordTheme::SurfaceAltColorHex()));
    rootLayout->addWidget(m_riskLabel);

    auto* identityLayout = new QHBoxLayout();
    m_refreshButton = new QPushButton(
        kernelText(
            "kernel.driver_image.refresh",
            QStringLiteral("刷新完整快照")),
        this);
    m_refreshButton->setIcon(QIcon(QStringLiteral(":/Icon/process_refresh.svg")));
    m_refreshButton->setToolTip(kernelText(
        "kernel.driver_image.tooltip.refresh",
        QStringLiteral("重新引用 DriverObject，并在真实加载器资源下刷新五字段与链状态")));
    m_refreshButton->setStyleSheet(KswordTheme::ThemedButtonStyle());
    m_identityLabel = new QLabel(this);
    m_identityLabel->setWordWrap(true);
    m_identityLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    identityLayout->addWidget(m_refreshButton);
    identityLayout->addWidget(m_identityLabel, 1);
    ks::ui::NormalizeToolbarRow(identityLayout);
    rootLayout->addLayout(identityLayout);

    m_table = new QTableWidget(
        static_cast<int>(std::size(FieldRows)),
        ColumnCount,
        this);
    // 映像字段编辑与恢复记录属于事务表单，隐藏全局快照对比。
    ks::ui::SetTableActionBarMode(m_table, ks::ui::TableActionBarMode::None);
    m_table->setHorizontalHeaderLabels({
        kernelText("kernel.driver_image.header.selected", QStringLiteral("选择")),
        kernelText("kernel.driver_image.header.field", QStringLiteral("字段")),
        kernelText("kernel.driver_image.header.current", QStringLiteral("当前值")),
        kernelText("kernel.driver_image.header.desired", QStringLiteral("目标值")),
        kernelText("kernel.driver_image.header.state", QStringLiteral("事务状态")),
        kernelText("kernel.driver_image.header.original", QStringLiteral("记录原值")),
        kernelText("kernel.driver_image.header.applied", QStringLiteral("已应用值")),
    });
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setSelectionMode(QAbstractItemView::SingleSelection);
    m_table->setAlternatingRowColors(true);
    m_table->verticalHeader()->setVisible(false);
    m_table->horizontalHeader()->setStretchLastSection(true);
    m_table->setStyleSheet(
        QStringLiteral(
            "QTableWidget{background:%1;alternate-background-color:%2;color:%3;}"
            "QHeaderView::section{background:%2;color:%3;border:1px solid %4;font-weight:600;}"
            "QTableWidget::item:selected{background:%5;color:%6;}")
            .arg(KswordTheme::SurfaceColorHex())
            .arg(KswordTheme::SurfaceAltColorHex())
            .arg(KswordTheme::TextPrimaryColorHex())
            .arg(KswordTheme::BorderColorHex())
            .arg(KswordTheme::PrimaryBlueHex)
            .arg(KswordTheme::OnAccentHex()));
    m_table->setColumnWidth(ColumnSelected, 62);
    m_table->setColumnWidth(ColumnField, 270);
    m_table->setColumnWidth(ColumnCurrent, 190);
    m_table->setColumnWidth(ColumnDesired, 190);
    m_table->setColumnWidth(ColumnState, 125);
    m_table->setColumnWidth(ColumnOriginal, 190);

    for (int row = 0; row < static_cast<int>(std::size(FieldRows)); ++row)
    {
        const FieldRowSpec& spec = FieldRows[row];
        m_table->setItem(row, ColumnSelected, selectionItem());
        m_table->setItem(
            row,
            ColumnField,
            readOnlyItem(kernelText(
                spec.translationKey,
                QString::fromLatin1(spec.fallbackText))));
        m_table->setItem(row, ColumnCurrent, readOnlyItem(QStringLiteral("-")));
        m_table->setItem(row, ColumnDesired, new QTableWidgetItem(QStringLiteral("0x0")));
        m_table->setItem(
            row,
            ColumnState,
            readOnlyItem(kernelText(
                "kernel.driver_image.state.inactive",
                QStringLiteral("未受管"))));
        m_table->setItem(row, ColumnOriginal, readOnlyItem(QStringLiteral("-")));
        m_table->setItem(row, ColumnApplied, readOnlyItem(QStringLiteral("-")));
    }
    rootLayout->addWidget(m_table, 2);

    auto* actionLayout = new QHBoxLayout();
    m_restoreLinkCheckBox = new QCheckBox(
        kernelText(
            "kernel.driver_image.restore_link",
            QStringLiteral("恢复时同时重新插入 PsLoadedModuleList")),
        this);
    m_applyButton = new QPushButton(
        kernelText("kernel.driver_image.apply", QStringLiteral("原子应用字段")),
        this);
    m_hideButton = new QPushButton(
        kernelText("kernel.driver_image.hide", QStringLiteral("从加载链隐藏")),
        this);
    m_restoreButton = new QPushButton(
        kernelText("kernel.driver_image.restore", QStringLiteral("恢复受管状态")),
        this);
    m_abandonButton = new QPushButton(
        kernelText("kernel.driver_image.abandon", QStringLiteral("放弃恢复记录")),
        this);

    m_applyButton->setIcon(QIcon(QStringLiteral(":/Icon/process_start.svg")));
    m_hideButton->setIcon(QIcon(QStringLiteral(":/Icon/process_uncritical.svg")));
    m_restoreButton->setIcon(QIcon(QStringLiteral(":/Icon/process_refresh.svg")));
    m_abandonButton->setIcon(QIcon(QStringLiteral(":/Icon/log_clear.svg")));
    m_applyButton->setToolTip(kernelText(
        "kernel.driver_image.tooltip.apply",
        QStringLiteral("按当前代次与期望快照一次性 CAS 修改所有勾选字段")));
    m_hideButton->setToolTip(kernelText(
        "kernel.driver_image.tooltip.hide",
        QStringLiteral("在 PsLoadedModuleResource 独占锁内按精确邻接摘链并自环")));
    m_restoreButton->setToolTip(kernelText(
        "kernel.driver_image.tooltip.restore",
        QStringLiteral("只恢复仍由本事务拥有的字段；链优先原位置，否则插入当前尾部")));
    m_abandonButton->setToolTip(kernelText(
        "kernel.driver_image.tooltip.abandon",
        QStringLiteral("保持当前字段和链不变，永久删除 KSword 保存的原值与恢复资格")));
    for (QPushButton* button :
         { m_applyButton, m_hideButton, m_restoreButton, m_abandonButton })
    {
        button->setStyleSheet(KswordTheme::ThemedButtonStyle());
    }

    actionLayout->addWidget(m_restoreLinkCheckBox);
    actionLayout->addStretch(1);
    actionLayout->addWidget(m_applyButton);
    actionLayout->addWidget(m_hideButton);
    actionLayout->addWidget(m_restoreButton);
    actionLayout->addWidget(m_abandonButton);
    ks::ui::NormalizeToolbarRow(actionLayout);
    rootLayout->addLayout(actionLayout);

    auto* detailLabel = new QLabel(
        kernelText(
            "kernel.driver_image.details",
            QStringLiteral("加载器资源、链与事务证据")),
        this);
    detailLabel->setStyleSheet(QStringLiteral("font-weight:600;"));
    rootLayout->addWidget(detailLabel);
    m_detailEditor = new ks::ui::StructuredFieldView(this);
    m_detailEditor->setMinimumHeight(210);
    rootLayout->addWidget(m_detailEditor, 1);

    auto* footer = new QWidget(this);
    auto* bottomLayout = new QHBoxLayout(footer);
    m_statusLabel = new QLabel(
        kernelText(
            "kernel.driver_image.status.waiting",
            QStringLiteral("状态：等待查询")),
        this);
    m_statusLabel->setWordWrap(true);
    m_statusLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    auto* closeButton = new QPushButton(
        kernelText("kernel.driver_image.close", QStringLiteral("关闭")),
        this);
    closeButton->setIcon(QIcon(QStringLiteral(":/Icon/process_details.svg")));
    closeButton->setStyleSheet(KswordTheme::ThemedButtonStyle());
    bottomLayout->addWidget(m_statusLabel, 1);
    bottomLayout->addWidget(closeButton);
    ks::ui::NormalizeToolbarRow(bottomLayout);
    ks::ui::StyleSecondaryFooter(footer);
    rootLayout->addWidget(footer);

    connect(closeButton, &QPushButton::clicked, this, &QDialog::accept);
    connect(m_refreshButton, &QPushButton::clicked, this, [this]() {
        refreshSnapshot();
    });
    connect(m_applyButton, &QPushButton::clicked, this, [this]() {
        applySelectedFields();
    });
    connect(m_hideButton, &QPushButton::clicked, this, [this]() {
        hideFromLoadedModuleList();
    });
    connect(m_restoreButton, &QPushButton::clicked, this, [this]() {
        restoreManagedState();
    });
    connect(m_abandonButton, &QPushButton::clicked, this, [this]() {
        abandonRecoveryRecord();
    });
    setActionsEnabled(false, false);
}

// 身份首查不要求 DriverStart 非零，因此字段被改坏后仍可按对象名进入事务恢复路径。
void KernelDriverImageEditorDialog::refreshSnapshot()
{
    setActionsEnabled(false, false);
    setStatus(
        kernelText(
            "kernel.driver_image.status.identity_querying",
            QStringLiteral("状态：正在引用 DriverObject...")),
        KswordTheme::InfoHex());

    const ksword::ark::DriverClient client;
    const auto identity =
        client.queryDriverObject(m_requestedDriverName.toStdWString());
    if (!identity.io.ok)
    {
        setStatus(
            kernelText(
                "kernel.driver_image.status.identity_failed",
                QStringLiteral("状态：DriverObject 查询失败：%1"))
                .arg(ioMessageText(identity.io.message)),
            KswordTheme::ErrorHex());
        return;
    }
    if (identity.lastStatus < 0 || identity.driverObjectAddress == 0U)
    {
        setStatus(
            kernelText(
                "kernel.driver_image.status.identity_unavailable",
                QStringLiteral("状态：R0 未返回可引用 DriverObject，NTSTATUS=%1"))
                .arg(ntStatusText(identity.lastStatus)),
            KswordTheme::ErrorHex());
        return;
    }

    m_canonicalDriverName = identity.driverName.empty()
        ? m_requestedDriverName
        : QString::fromStdWString(identity.driverName);
    // 不把可能已被本事务修改的当前 DriverStart 当成稳定身份。
    // 零基址让 R0 先按精确对象查旧记录；无记录时再从实时字段建立初始身份。
    m_moduleBase = 0U;
    m_driverObjectAddress = identity.driverObjectAddress;

    ksword::ark::DriverImageControlResult result{};
    (void)queryTransaction(result, true);
}

// 每个破坏动作执行前都调用本函数刷新代次和邻接；目标输入格可选择保留。
bool KernelDriverImageEditorDialog::queryTransaction(
    ksword::ark::DriverImageControlResult& resultOut,
    const bool resetDesiredValues)
{
    if (m_canonicalDriverName.isEmpty() || m_driverObjectAddress == 0U)
    {
        return false;
    }

    const ksword::ark::DriverClient client;
    resultOut = client.queryDriverImage(
        m_moduleBase,
        m_canonicalDriverName.toStdWString(),
        m_driverObjectAddress);
    if (!resultOut.io.ok)
    {
        setStatus(
            kernelText(
                "kernel.driver_image.status.transaction_query_failed",
                QStringLiteral("状态：镜像事务查询失败：%1"))
                .arg(ioMessageText(resultOut.io.message)),
            KswordTheme::ErrorHex());
        return false;
    }

    applyResultToView(resultOut, resetDesiredValues);
    if (resultOut.lastStatus < 0)
    {
        setStatus(
            kernelText(
                "kernel.driver_image.status.transaction_failed",
                QStringLiteral("状态：R0 事务查询失败，NTSTATUS=%1，loader=%2"))
                .arg(ntStatusText(resultOut.lastStatus))
                .arg(ntStatusText(resultOut.loaderStatus)),
            KswordTheme::ErrorHex());
        return false;
    }

    setStatus(
        kernelText(
            "kernel.driver_image.status.ready",
            QStringLiteral("状态：快照已锁定；generation=%1，字段掩码=%2，loader=%3"))
            .arg(resultOut.generation)
            .arg(maskText(resultOut.managedFieldMask))
            .arg(ntStatusText(resultOut.loaderStatus)),
        KswordTheme::SuccessHex());
    return true;
}

// 原子批量修改只使用刚查询的 currentValues 作为 expected；解析不筛选地址归属。
void KernelDriverImageEditorDialog::applySelectedFields()
{
    const std::uint32_t fieldMask = selectedFieldMask();
    if (fieldMask == 0U)
    {
        QMessageBox::warning(
            this,
            windowTitle(),
            kernelText(
                "kernel.driver_image.no_fields",
                QStringLiteral("至少勾选一个要修改的字段。")));
        return;
    }

    ksword::ark::DriverImageControlResult snapshot{};
    if (!queryTransaction(snapshot, false))
    {
        return;
    }
    ksword::ark::DriverImageValues desiredValues{};
    QString parseError;
    if (!parseDesiredValues(desiredValues, parseError))
    {
        QMessageBox::warning(this, windowTitle(), parseError);
        return;
    }

    const QString warning = kernelText(
        "kernel.driver_image.apply.warning",
        QStringLiteral("即将对 %1 原子修改勾选字段（mask=%2，generation=%3）。R0 不检查指针是否映射、可执行、属于目标镜像或满足 ABI；DriverSize/SizeOfImage 只验证真实 ULONG 宽度。错误值可能立即蓝屏、破坏卸载与转储，或触发 PatchGuard。"))
        .arg(m_canonicalDriverName)
        .arg(maskText(fieldMask))
        .arg(snapshot.generation);
    if (!confirmDanger(warning, kernelText("kernel.driver_image.apply", QStringLiteral("原子应用字段"))))
    {
        return;
    }

    const ksword::ark::DriverClient client;
    const auto result = client.applyDriverImageFields(
        m_moduleBase,
        m_canonicalDriverName.toStdWString(),
        fieldMask,
        m_driverObjectAddress,
        snapshot.generation,
        snapshot.currentValues,
        desiredValues);
    if (!result.io.ok)
    {
        setStatus(ioMessageText(result.io.message), KswordTheme::ErrorHex());
        return;
    }

    applyResultToView(result, result.lastStatus >= 0);
    setStatus(
        kernelText(
            "kernel.driver_image.status.applied",
            QStringLiteral("状态：字段应用完成，NTSTATUS=%1，changed=%2，generation=%3"))
            .arg(ntStatusText(result.lastStatus))
            .arg(maskText(result.changedFieldMask))
            .arg(result.generation),
        result.lastStatus >= 0
            ? KswordTheme::WarningHex()
            : KswordTheme::ErrorHex());
}

// 加载链摘除始终回传查询到的双向邻接，R0 再在真实 ERESOURCE 下验证。
void KernelDriverImageEditorDialog::hideFromLoadedModuleList()
{
    ksword::ark::DriverImageControlResult snapshot{};
    if (!queryTransaction(snapshot, false))
    {
        return;
    }

    const QString warning = kernelText(
        "kernel.driver_image.hide.warning",
        QStringLiteral("即将把 %1 从 PsLoadedModuleList 摘链并把其 InLoadOrderLinks 设为自环。该动作不会卸载镜像，但可能立即触发 PatchGuard，使卸载、崩溃转储、符号解析和模块枚举失效；隐藏 KSword 自身也可能让恢复通道在崩溃前来不及执行。"))
        .arg(m_canonicalDriverName);
    if (!confirmDanger(warning, kernelText("kernel.driver_image.hide", QStringLiteral("从加载链隐藏"))))
    {
        return;
    }

    const ksword::ark::DriverClient client;
    const auto result = client.hideDriverImage(
        m_moduleBase,
        m_canonicalDriverName.toStdWString(),
        m_driverObjectAddress,
        snapshot.generation,
        snapshot.currentLinkFlink,
        snapshot.currentLinkBlink);
    if (!result.io.ok)
    {
        setStatus(ioMessageText(result.io.message), KswordTheme::ErrorHex());
        return;
    }

    applyResultToView(result, false);
    setStatus(
        kernelText(
            "kernel.driver_image.status.hidden",
            QStringLiteral("状态：摘链请求完成，NTSTATUS=%1，generation=%2"))
            .arg(ntStatusText(result.lastStatus))
            .arg(result.generation),
        result.lastStatus >= 0
            ? KswordTheme::WarningHex()
            : KswordTheme::ErrorHex());
}

// 恢复仅覆盖仍等于本事务 applied 值的字段；第三方值会进入 conflict 而不被覆盖。
void KernelDriverImageEditorDialog::restoreManagedState()
{
    ksword::ark::DriverImageControlResult snapshot{};
    if (!queryTransaction(snapshot, false))
    {
        return;
    }

    const std::uint32_t fieldMask = selectedFieldMask();
    const bool restoreLink =
        m_restoreLinkCheckBox != nullptr &&
        m_restoreLinkCheckBox->isChecked();
    if (fieldMask == 0U && !restoreLink)
    {
        QMessageBox::warning(
            this,
            windowTitle(),
            kernelText(
                "kernel.driver_image.restore.empty",
                QStringLiteral("没有勾选字段，也没有选择恢复加载链。")));
        return;
    }

    const QString warning = kernelText(
        "kernel.driver_image.restore.warning",
        QStringLiteral("即将恢复 %1 的受管字段（mask=%2）%3。只有 current==applied 的值会恢复；加载链原邻居仍相邻时回原位，否则插入当前尾部。竞争值保持不变并报告冲突。"))
        .arg(m_canonicalDriverName)
        .arg(maskText(fieldMask))
        .arg(restoreLink
            ? kernelText(
                "kernel.driver_image.restore.with_link",
                QStringLiteral("，并重新插入 PsLoadedModuleList"))
            : QString());
    if (!confirmDanger(warning, kernelText("kernel.driver_image.restore", QStringLiteral("恢复受管状态"))))
    {
        return;
    }

    const ksword::ark::DriverClient client;
    const auto result = client.restoreDriverImage(
        m_moduleBase,
        m_canonicalDriverName.toStdWString(),
        fieldMask,
        restoreLink,
        m_driverObjectAddress,
        snapshot.generation);
    if (!result.io.ok)
    {
        setStatus(ioMessageText(result.io.message), KswordTheme::ErrorHex());
        return;
    }

    applyResultToView(result, result.lastStatus >= 0);
    const QString position =
        (result.responseFlags &
         KSWORD_ARK_DRIVER_IMAGE_RESPONSE_FLAG_RESTORED_ORIGINAL_POSITION) != 0U
        ? kernelText(
            "kernel.driver_image.restore.position.original",
            QStringLiteral("原位置"))
        : ((result.responseFlags &
            KSWORD_ARK_DRIVER_IMAGE_RESPONSE_FLAG_RESTORED_LIST_TAIL) != 0U
            ? kernelText(
                "kernel.driver_image.restore.position.tail",
                QStringLiteral("当前尾部"))
            : QStringLiteral("-"));
    setStatus(
        kernelText(
            "kernel.driver_image.status.restored",
            QStringLiteral("状态：恢复完成，NTSTATUS=%1，changed=%2，链位置=%3"))
            .arg(ntStatusText(result.lastStatus))
            .arg(maskText(result.changedFieldMask))
            .arg(position),
        result.lastStatus >= 0
            ? KswordTheme::SuccessHex()
            : KswordTheme::ErrorHex());
}

// 放弃是不可逆的记录删除；当前字段、隐藏链和第三方冲突全部原样保留。
void KernelDriverImageEditorDialog::abandonRecoveryRecord()
{
    ksword::ark::DriverImageControlResult snapshot{};
    if (!queryTransaction(snapshot, false))
    {
        return;
    }
    if ((snapshot.responseFlags &
         KSWORD_ARK_DRIVER_IMAGE_RESPONSE_FLAG_RECORD_PRESENT) == 0U)
    {
        return;
    }

    const QString warning = kernelText(
        "kernel.driver_image.abandon.warning",
        QStringLiteral("即将永久放弃 %1 的全部恢复记录。当前任意字段值、隐藏链状态和冲突都不会改变；KSword 将释放 DriverObject 引用，并失去自动恢复所需的原值与邻居。"))
        .arg(m_canonicalDriverName);
    if (!confirmDanger(warning, kernelText("kernel.driver_image.abandon", QStringLiteral("放弃恢复记录"))))
    {
        return;
    }

    const ksword::ark::DriverClient client;
    const auto result = client.abandonDriverImage(
        m_moduleBase,
        m_canonicalDriverName.toStdWString(),
        m_driverObjectAddress,
        snapshot.generation);
    if (!result.io.ok)
    {
        setStatus(ioMessageText(result.io.message), KswordTheme::ErrorHex());
        return;
    }

    applyResultToView(result, false);
    setStatus(
        kernelText(
            "kernel.driver_image.status.abandoned",
            QStringLiteral("状态：恢复记录已放弃，NTSTATUS=%1；当前危险状态保持不变"))
            .arg(ntStatusText(result.lastStatus)),
        result.lastStatus >= 0
            ? KswordTheme::WarningHex()
            : KswordTheme::ErrorHex());
}

// 响应是 UI 的唯一状态源；任何失败响应也会刷新冲突与当前值，避免展示旧快照。
void KernelDriverImageEditorDialog::applyResultToView(
    const ksword::ark::DriverImageControlResult& result,
    const bool resetDesiredValues)
{
    if (!result.driverName.empty())
    {
        m_canonicalDriverName =
            QString::fromStdWString(result.driverName);
    }
    m_moduleBase = result.targetModuleBase;
    m_driverObjectAddress = result.driverObjectAddress;
    m_currentLinkFlink = result.currentLinkFlink;
    m_currentLinkBlink = result.currentLinkBlink;
    m_generation = result.generation;
    m_responseFlags = result.responseFlags;
    m_managedFieldMask = result.managedFieldMask;

    const bool recordPresent =
        (result.responseFlags &
         KSWORD_ARK_DRIVER_IMAGE_RESPONSE_FLAG_RECORD_PRESENT) != 0U;
    for (int row = 0; row < static_cast<int>(std::size(FieldRows)); ++row)
    {
        const std::uint32_t field = FieldRows[row].mask;
        const std::uint64_t current = fieldValue(result.currentValues, row);
        m_currentValues[static_cast<std::size_t>(row)] = current;
        m_table->item(row, ColumnCurrent)->setText(pointerText(current));
        if (resetDesiredValues)
        {
            m_table->item(row, ColumnDesired)->setText(pointerText(current));
        }

        QString stateText;
        if ((result.conflictFieldMask & field) != 0U)
        {
            stateText = kernelText(
                "kernel.driver_image.state.conflict",
                QStringLiteral("外部冲突"));
        }
        else if ((result.ownedFieldMask & field) != 0U)
        {
            stateText = kernelText(
                "kernel.driver_image.state.owned",
                QStringLiteral("事务拥有"));
        }
        else if ((result.managedFieldMask & field) != 0U)
        {
            stateText = kernelText(
                "kernel.driver_image.state.managed",
                QStringLiteral("已记录"));
        }
        else
        {
            stateText = kernelText(
                "kernel.driver_image.state.inactive",
                QStringLiteral("未受管"));
        }
        m_table->item(row, ColumnState)->setText(stateText);
        m_table->item(row, ColumnOriginal)->setText(
            recordPresent && (result.managedFieldMask & field) != 0U
                ? pointerText(fieldValue(result.originalValues, row))
                : QStringLiteral("-"));
        m_table->item(row, ColumnApplied)->setText(
            recordPresent && (result.managedFieldMask & field) != 0U
                ? pointerText(fieldValue(result.appliedValues, row))
                : QStringLiteral("-"));
    }

    m_identityLabel->setText(
        kernelText(
            "kernel.driver_image.identity",
            QStringLiteral("对象：%1    DriverObject=%2    冻结模块基址=%3"))
            .arg(
                m_canonicalDriverName,
                pointerText(m_driverObjectAddress),
                pointerText(m_moduleBase)));
    updateDetails(result);
    setActionsEnabled(result.lastStatus >= 0, recordPresent);
}

// 详情文本保留每一个地址与标志，便于复制到调试器核对，而不只给“成功/失败”摘要。
void KernelDriverImageEditorDialog::updateDetails(
    const ksword::ark::DriverImageControlResult& result)
{
    QString linkState = kernelText(
        "kernel.driver_image.link.unknown",
        QStringLiteral("未知/不可用"));
    if ((result.responseFlags &
         KSWORD_ARK_DRIVER_IMAGE_RESPONSE_FLAG_LINK_CONFLICT) != 0U)
    {
        linkState = kernelText(
            "kernel.driver_image.link.conflict",
            QStringLiteral("冲突"));
    }
    else if ((result.responseFlags &
              KSWORD_ARK_DRIVER_IMAGE_RESPONSE_FLAG_LINK_HIDDEN) != 0U)
    {
        linkState = kernelText(
            "kernel.driver_image.link.hidden",
            QStringLiteral("隐藏/自环"));
    }
    else if ((result.responseFlags &
              KSWORD_ARK_DRIVER_IMAGE_RESPONSE_FLAG_LINK_VISIBLE) != 0U)
    {
        linkState = kernelText(
            "kernel.driver_image.link.visible",
            QStringLiteral("可见/双向一致"));
    }

    ks::ui::FieldDocument detail;
    detail.section(QStringLiteral("事务状态"));
    detail.field(QStringLiteral("Protocol"), QString::number(result.version));
    detail.field(QStringLiteral("Action"), QString::number(result.action));
    detail.field(QStringLiteral("State"), QString::number(result.state));
    detail.field(QStringLiteral("Generation"), QString::number(result.generation));
    detail.field(QStringLiteral("LastStatus"), ntStatusText(result.lastStatus));
    detail.field(QStringLiteral("LoaderStatus"), ntStatusText(result.loaderStatus));
    detail.section(QStringLiteral("身份"));
    detail.field(QStringLiteral("DriverName"), m_canonicalDriverName);
    detail.field(QStringLiteral("TargetModuleBase"), pointerText(result.targetModuleBase));
    detail.field(QStringLiteral("DriverObject"), pointerText(result.driverObjectAddress));
    detail.field(QStringLiteral("SelfDriverObject"), pointerText(result.selfDriverObjectAddress));
    detail.section(QStringLiteral("掩码"));
    detail.field(QStringLiteral("Managed"), maskText(result.managedFieldMask));
    detail.field(QStringLiteral("Owned"), maskText(result.ownedFieldMask));
    detail.field(QStringLiteral("Conflict"), maskText(result.conflictFieldMask));
    detail.field(QStringLiteral("Changed"), maskText(result.changedFieldMask));
    detail.field(QStringLiteral("ResponseFlags"), maskText(result.responseFlags));
    detail.field(QStringLiteral("LayoutFlags"), maskText(result.layoutFlags));
    detail.section(QStringLiteral("加载器资源"));
    detail.field(QStringLiteral("LoaderEntry"), pointerText(result.loaderEntryAddress));
    detail.field(QStringLiteral("LoaderLink"), pointerText(result.loaderLinkAddress));
    detail.field(QStringLiteral("PsLoadedModuleList"), pointerText(result.listHeadAddress));
    detail.field(QStringLiteral("PsLoadedModuleResource"), pointerText(result.listResourceAddress));
    detail.section(QStringLiteral("链"));
    detail.field(QStringLiteral("LinkState"), linkState);
    detail.field(QStringLiteral("Current.Flink"), pointerText(result.currentLinkFlink));
    detail.field(QStringLiteral("Current.Blink"), pointerText(result.currentLinkBlink));
    detail.field(QStringLiteral("Original.Flink"), pointerText(result.originalLinkFlink));
    detail.field(QStringLiteral("Original.Blink"), pointerText(result.originalLinkBlink));
    detail.note(kernelText("kernel.driver_image.detail.policy",
        QStringLiteral("Policy=warn-only; no target-class or requested-value restrictions.\nRestore uses ownership checks; competing values are reported and preserved.")));
    m_detailEditor->setDocument(detail);
}

// 按响应能力启用按钮；这只是防止无身份/无记录请求，不按目标种类限制。
void KernelDriverImageEditorDialog::setActionsEnabled(
    const bool querySucceeded,
    const bool recordPresent)
{
    const bool loaderReady =
        (m_responseFlags &
         KSWORD_ARK_DRIVER_IMAGE_RESPONSE_FLAG_LOADER_AVAILABLE) != 0U &&
        (m_responseFlags &
         KSWORD_ARK_DRIVER_IMAGE_RESPONSE_FLAG_LIST_LOCK_AVAILABLE) != 0U;
    const bool linkVisible =
        (m_responseFlags &
         KSWORD_ARK_DRIVER_IMAGE_RESPONSE_FLAG_LINK_VISIBLE) != 0U;
    const bool linkTracked =
        (m_responseFlags &
         (KSWORD_ARK_DRIVER_IMAGE_RESPONSE_FLAG_LINK_HIDDEN |
          KSWORD_ARK_DRIVER_IMAGE_RESPONSE_FLAG_LINK_OWNED |
          KSWORD_ARK_DRIVER_IMAGE_RESPONSE_FLAG_LINK_CONFLICT)) != 0U;

    m_applyButton->setEnabled(querySucceeded);
    m_hideButton->setEnabled(querySucceeded && loaderReady && linkVisible);
    m_restoreButton->setEnabled(querySucceeded && recordPresent);
    m_abandonButton->setEnabled(querySucceeded && recordPresent);
    m_restoreLinkCheckBox->setEnabled(
        querySucceeded && recordPresent && linkTracked);
    m_restoreLinkCheckBox->setChecked(linkTracked);
}

// 状态标签使用显式主题色，不继承父窗口可能存在的透明/弱对比样式。
void KernelDriverImageEditorDialog::setStatus(
    const QString& text,
    const QString& colorHex)
{
    m_statusLabel->setText(text);
    m_statusLabel->setStyleSheet(
        QStringLiteral("color:%1;font-weight:600;").arg(colorHex));
}

// 每行复选框直接映射共享协议位，支持任意组合的单字段或批量事务。
std::uint32_t KernelDriverImageEditorDialog::selectedFieldMask() const
{
    std::uint32_t mask = 0U;
    for (int row = 0; row < static_cast<int>(std::size(FieldRows)); ++row)
    {
        const QTableWidgetItem* item =
            m_table->item(row, ColumnSelected);
        if (item != nullptr && item->checkState() == Qt::Checked)
        {
            mask |= FieldRows[row].mask;
        }
    }
    return mask;
}

// 未勾选字段沿用当前值；勾选字段接受 0、十进制和 0x 十六进制完整 64 位数。
bool KernelDriverImageEditorDialog::parseDesiredValues(
    ksword::ark::DriverImageValues& valuesOut,
    QString& errorOut) const
{
    const std::uint32_t fieldMask = selectedFieldMask();
    for (int row = 0; row < static_cast<int>(std::size(FieldRows)); ++row)
    {
        setFieldValue(
            valuesOut,
            row,
            m_currentValues[static_cast<std::size_t>(row)]);
        if ((fieldMask & FieldRows[row].mask) == 0U)
        {
            continue;
        }

        std::uint64_t value = 0U;
        const QTableWidgetItem* item =
            m_table->item(row, ColumnDesired);
        if (item == nullptr || !parseUnsigned64(item->text(), value))
        {
            errorOut = kernelText(
                "kernel.driver_image.invalid_value",
                QStringLiteral("%1 的目标值无效；允许 0、十进制和 0x 十六进制。"))
                .arg(m_table->item(row, ColumnField)->text());
            return false;
        }
        if (FieldRows[row].naturalUlong &&
            value > std::numeric_limits<std::uint32_t>::max())
        {
            errorOut = kernelText(
                "kernel.driver_image.size_out_of_range",
                QStringLiteral("%1 是内核 ULONG 字段，目标值不能超过 0xFFFFFFFF；该检查只防止协议静默截断。"))
                .arg(m_table->item(row, ColumnField)->text());
            return false;
        }
        setFieldValue(valuesOut, row, value);
    }
    return true;
}

// 两步确认只证明用户已读警告；动作名与按钮文案一致，不形成策略限制。
bool KernelDriverImageEditorDialog::confirmDanger(
    const QString& warningText,
    const QString& phrase) const
{
    auto* self = const_cast<KernelDriverImageEditorDialog*>(this);
    if (QMessageBox::warning(
        self,
        windowTitle(),
        warningText,
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No) != QMessageBox::Yes)
    {
        return false;
    }

    // 最终确认改为直接点击：不再要求输入确认短语，phrase 仅用于说明本次动作。
    return QMessageBox::warning(
        self,
        windowTitle(),
        kernelText(
            "kernel.driver_image.confirm.final",
            QStringLiteral("确认执行“%1”？请确保已知晓上述风险。"))
            .arg(phrase),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No) == QMessageBox::Yes;
}

std::uint64_t KernelDriverImageEditorDialog::fieldValue(
    const ksword::ark::DriverImageValues& values,
    const int row)
{
    switch (row)
    {
    case 0: return values.driverStart;
    case 1: return values.driverSize;
    case 2: return values.driverSection;
    case 3: return values.kldrDllBase;
    case 4: return values.kldrSizeOfImage;
    default: return 0U;
    }
}

void KernelDriverImageEditorDialog::setFieldValue(
    ksword::ark::DriverImageValues& values,
    const int row,
    const std::uint64_t value)
{
    switch (row)
    {
    case 0: values.driverStart = value; break;
    case 1: values.driverSize = value; break;
    case 2: values.driverSection = value; break;
    case 3: values.kldrDllBase = value; break;
    case 4: values.kldrSizeOfImage = value; break;
    default: break;
    }
}

QString KernelDriverImageEditorDialog::pointerText(
    const std::uint64_t address)
{
    return QStringLiteral("0x%1")
        .arg(static_cast<qulonglong>(address), 16, 16, QChar('0'))
        .toUpper();
}

QString KernelDriverImageEditorDialog::ntStatusText(const long status)
{
    return QStringLiteral("0x%1")
        .arg(
            static_cast<qulonglong>(
                static_cast<std::uint32_t>(status)),
            8,
            16,
            QChar('0'))
        .toUpper();
}

bool KernelDriverImageEditorDialog::parseUnsigned64(
    const QString& text,
    std::uint64_t& valueOut)
{
    bool ok = false;
    const qulonglong value = text.trimmed().toULongLong(&ok, 0);
    if (!ok)
    {
        return false;
    }
    valueOut = static_cast<std::uint64_t>(value);
    return true;
}
