// ============================================================
// ProcessDock.ColumnChooser.cpp
// 作用：
// - 实现进程列表的“添加/减少列”能力（选择列对话框 + 逐列显隐入口）；
// - 维护用户列选择的持久化，使其跨会话与跨视图切换保留；
// - 根据当前可见列计算后台采集需求位图，避免为隐藏列付出查询成本。
// 说明：
// - 列的取值与格式化仍在 ProcessDock.cpp 中，本文件只负责“显示哪些列”。
// ============================================================

#include "ProcessDock.h"

#include "../theme.h"
#include "../Internationalization/LanguageManager.h"

#include <QCheckBox>
#include <QComboBox>
#include <QDialog>
#include <QDialogButtonBox>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QIcon>
#include <QInputDialog>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QScrollArea>
#include <QSettings>
#include <QSignalBlocker>
#include <QStringList>
#include <QTableView>
#include <QVBoxLayout>
#include <QVariant>
#include <QWidget>

#include <cstddef>
#include <vector>

namespace
{
    // ProcessColumnLayoutSettingsGroup：
    // - QSettings 中保存进程表列布局的分组名；
    // - 只存“与视图默认不同”的项，默认列集合调整后不会被旧配置钉死。
    constexpr const char* ProcessColumnLayoutSettingsGroup = "ProcessDock/ColumnLayout";

    // ProcessCustomViewSettingsGroup：
    // - QSettings 中保存用户自定义视图的分组名；
    // - 每个视图一条：键为视图名，值为逗号分隔的列逻辑索引。
    constexpr const char* ProcessCustomViewSettingsGroup = "ProcessDock/CustomViews";

    // 视图下拉项图标：监视类预设用列表图标，其余内置预设用进程图标，自定义视图不带图标便于区分。
    constexpr const char* ProcessViewMonitorIconPath = ":/Icon/process_list.svg";
    constexpr const char* ProcessViewPresetIconPath = ":/Icon/process_main.svg";

    // processColumnChooserText 作用：读取“选择列”对话框的界面文案。
    QString processColumnChooserText(const char* const key, const QString& sourceText)
    {
        return ks::i18n::contextText(QString::fromLatin1(key), sourceText);
    }
}

ProcessDock::ProcessColumnGroup ProcessDock::processColumnGroupOf(const TableColumn column)
{
    // 输入：列枚举值。
    // 处理：按语义归入“选择列”对话框中的分组。
    // 返回：分组枚举；仅用于对话框展示与检索，不参与任何数据读写。
    switch (column)
    {
    case TableColumn::Cpu:
    case TableColumn::CpuCore:
    case TableColumn::Disk:
    case TableColumn::Gpu:
    case TableColumn::Net:
    case TableColumn::CpuTime:
    case TableColumn::CycleTime:
    case TableColumn::BasePriority:
    case TableColumn::ThreadCount:
    case TableColumn::PowerThrottling:
    case TableColumn::GpuEngine:
    case TableColumn::GpuDedicatedMemory:
    case TableColumn::GpuSharedMemory:
        return ProcessColumnGroup::Performance;

    case TableColumn::Ram:
    case TableColumn::WorkingSet:
    case TableColumn::PeakWorkingSet:
    case TableColumn::WorkingSetDelta:
    case TableColumn::ActivePrivateWorkingSet:
    case TableColumn::PrivateWorkingSet:
    case TableColumn::SharedWorkingSet:
    case TableColumn::CommitSize:
    case TableColumn::PagedPool:
    case TableColumn::NonPagedPool:
    case TableColumn::PageFaults:
    case TableColumn::PageFaultDelta:
        return ProcessColumnGroup::Memory;

    case TableColumn::IoReads:
    case TableColumn::IoWrites:
    case TableColumn::IoOther:
    case TableColumn::IoReadBytes:
    case TableColumn::IoWriteBytes:
    case TableColumn::IoOtherBytes:
        return ProcessColumnGroup::Io;

    case TableColumn::Signature:
    case TableColumn::IsAdmin:
    case TableColumn::PplLevel:
    case TableColumn::UacVirtualization:
    case TableColumn::DataExecutionPrevention:
    case TableColumn::ControlFlowGuard:
    case TableColumn::HardwareStackProtection:
    case TableColumn::EnterpriseContext:
    case TableColumn::JobObject:
        return ProcessColumnGroup::Security;

    case TableColumn::Protection:
    case TableColumn::Ppl:
    case TableColumn::HandleTable:
    case TableColumn::SectionObject:
    case TableColumn::R0Status:
        return ProcessColumnGroup::Kernel;

    default:
        return ProcessColumnGroup::General;
    }
}

QString ProcessDock::processColumnGroupTitle(const ProcessColumnGroup group)
{
    // 输入：列分组枚举。
    // 处理：返回“选择列”对话框中的分组标题。
    // 返回：本地化标题文本。
    switch (group)
    {
    case ProcessColumnGroup::Performance:
        return processColumnChooserText("process.columns.group.performance", QStringLiteral("性能"));
    case ProcessColumnGroup::Memory:
        return processColumnChooserText("process.columns.group.memory", QStringLiteral("内存"));
    case ProcessColumnGroup::Io:
        return processColumnChooserText("process.columns.group.io", QStringLiteral("磁盘 I/O"));
    case ProcessColumnGroup::Security:
        return processColumnChooserText("process.columns.group.security", QStringLiteral("安全与策略"));
    case ProcessColumnGroup::Kernel:
        return processColumnChooserText("process.columns.group.kernel", QStringLiteral("内核扩展"));
    case ProcessColumnGroup::General:
    default:
        return processColumnChooserText("process.columns.group.general", QStringLiteral("常规"));
    }
}

bool ProcessDock::isProcessColumnVisible(const TableColumn column) const
{
    if (m_processTable == nullptr)
    {
        return false;
    }

    const int columnIndex = toColumnIndex(column);
    if (columnIndex < 0 || columnIndex >= static_cast<int>(TableColumn::Count))
    {
        return false;
    }
    return !m_processTable->isColumnHidden(columnIndex);
}

void ProcessDock::applyUserColumnVisibilityOverrides()
{
    // 输入：m_userColumnVisibilityOverride 中记录的逐列选择。
    // 处理：在视图预设铺好基础显隐之后，把用户选择叠加回去。
    // 返回：无。
    if (m_processTable == nullptr || m_userColumnVisibilityOverride.isEmpty())
    {
        return;
    }

    for (auto overrideIt = m_userColumnVisibilityOverride.constBegin();
        overrideIt != m_userColumnVisibilityOverride.constEnd();
        ++overrideIt)
    {
        const int columnIndex = overrideIt.key();
        if (columnIndex < 0 || columnIndex >= static_cast<int>(TableColumn::Count))
        {
            continue;
        }

        // R0-only 列在整轮扩展不可用时由 applyR0ColumnAvailability 统一隐藏；
        // 这里不覆盖该判定，避免显示一整列 Unavailable 占位文本。
        if (overrideIt.value() && m_autoHideUnavailableR0Columns)
        {
            const TableColumn column = static_cast<TableColumn>(columnIndex);
            if (processColumnGroupOf(column) == ProcessColumnGroup::Kernel)
            {
                continue;
            }
        }

        m_processTable->setColumnHidden(columnIndex, !overrideIt.value());
    }
}

void ProcessDock::setProcessColumnVisible(
    const int columnIndex,
    const bool visible,
    const bool persistImmediately)
{
    if (m_processTable == nullptr ||
        columnIndex < 0 ||
        columnIndex >= static_cast<int>(TableColumn::Count))
    {
        return;
    }

    // R0-only 列在扩展整轮不可用时不允许手动显示：整列都会是 Unavailable，没有信息量。
    const TableColumn column = static_cast<TableColumn>(columnIndex);
    if (visible &&
        m_autoHideUnavailableR0Columns &&
        processColumnGroupOf(column) == ProcessColumnGroup::Kernel)
    {
        kLogEvent logEvent;
        info << logEvent
            << "[ProcessDock] 忽略 R0-only 列手动显示请求：当前所有可见行 R0 扩展均为 Unavailable, column="
            << columnIndex
            << eol;
        return;
    }

    m_userColumnVisibilityOverride.insert(columnIndex, visible);
    m_processTable->setColumnHidden(columnIndex, !visible);

    if (persistImmediately)
    {
        saveProcessColumnLayoutToSettings();
        applyAdaptiveColumnWidths();

        // 新显示的列可能需要额外采集（GDI 对象、作业、缓解策略、显存等）：
        // 立刻强制刷新一轮，用户不必等到下一个周期才看到真实数据。
        const std::uint32_t nextDemandFlags = currentProcessDetailDemandFlags();
        const bool detailDemandChanged =
            nextDemandFlags != m_lastProcessDetailDemandFlags;
        if (detailDemandChanged)
        {
            m_lastProcessDetailDemandFlags = nextDemandFlags;
        }
        if (detailDemandChanged || column == TableColumn::CpuCore)
        {
            // CPU核心列显隐决定单系统 ETW 会话生命周期，需要立即刷新而不是等待周期定时器。
            requestAsyncRefresh(true);
        }
    }
}

void ProcessDock::resetProcessColumnsToViewDefault()
{
    m_userColumnVisibilityOverride.clear();
    saveProcessColumnLayoutToSettings();

    // 当前是自定义视图时，“默认”指的是该自定义视图保存下来的列集合；
    // 否则回到内置预设的默认列。
    const int customIndex = currentCustomViewIndex();
    if (customIndex >= 0)
    {
        applyCustomView(customIndex);
    }
    else
    {
        applyViewMode(currentViewMode());
    }

    m_lastProcessDetailDemandFlags = currentProcessDetailDemandFlags();
    // 恢复内置预设可能显示/隐藏 CPU核心列，立即同步唯一 ETW 会话生命周期。
    requestAsyncRefresh(true);

    kLogEvent logEvent;
    info << logEvent << "[ProcessDock] 进程表列布局已恢复为当前视图默认值。" << eol;
}

void ProcessDock::loadProcessColumnLayoutFromSettings()
{
    // 输入：QSettings 中保存的逐列选择。
    // 处理：只读取仍然有效的列索引，忽略历史版本遗留的越界项。
    // 返回：无；结果写入 m_userColumnVisibilityOverride，由调用方决定何时应用。
    m_userColumnVisibilityOverride.clear();

    QSettings settings;
    settings.beginGroup(QString::fromLatin1(ProcessColumnLayoutSettingsGroup));
    const QStringList savedKeys = settings.childKeys();
    for (const QString& savedKey : savedKeys)
    {
        bool parseOk = false;
        const int columnIndex = savedKey.toInt(&parseOk);
        if (!parseOk || columnIndex < 0 || columnIndex >= static_cast<int>(TableColumn::Count))
        {
            continue;
        }
        m_userColumnVisibilityOverride.insert(columnIndex, settings.value(savedKey).toBool());
    }
    settings.endGroup();

    if (!m_userColumnVisibilityOverride.isEmpty())
    {
        kLogEvent logEvent;
        info << logEvent
            << "[ProcessDock] 已从配置恢复进程表列布局, overrideCount="
            << m_userColumnVisibilityOverride.size()
            << eol;
    }
}

void ProcessDock::saveProcessColumnLayoutToSettings() const
{
    QSettings settings;
    settings.beginGroup(QString::fromLatin1(ProcessColumnLayoutSettingsGroup));
    settings.remove(QString());
    for (auto overrideIt = m_userColumnVisibilityOverride.constBegin();
        overrideIt != m_userColumnVisibilityOverride.constEnd();
        ++overrideIt)
    {
        settings.setValue(QString::number(overrideIt.key()), overrideIt.value());
    }
    settings.endGroup();
}

void ProcessDock::loadCustomViewsFromSettings()
{
    // 输入：QSettings 中保存的自定义视图。
    // 处理：解析逗号分隔的列索引，丢弃越界项与空视图。
    // 返回：无；结果写入 m_customViews。
    m_customViews.clear();

    QSettings settings;
    settings.beginGroup(QString::fromLatin1(ProcessCustomViewSettingsGroup));
    const QStringList savedNames = settings.childKeys();
    for (const QString& savedName : savedNames)
    {
        const QString trimmedName = savedName.trimmed();
        if (trimmedName.isEmpty())
        {
            continue;
        }

        ProcessCustomView customView;
        customView.name = trimmedName;
        const QStringList columnTexts =
            settings.value(savedName).toString().split(QChar(','), Qt::SkipEmptyParts);
        for (const QString& columnText : columnTexts)
        {
            bool parseOk = false;
            const int columnIndex = columnText.trimmed().toInt(&parseOk);
            if (!parseOk || columnIndex < 0 || columnIndex >= static_cast<int>(TableColumn::Count))
            {
                continue;
            }
            customView.visibleColumns.push_back(columnIndex);
        }

        if (!customView.visibleColumns.empty())
        {
            m_customViews.push_back(std::move(customView));
        }
    }
    settings.endGroup();
}

void ProcessDock::saveCustomViewsToSettings() const
{
    QSettings settings;
    settings.beginGroup(QString::fromLatin1(ProcessCustomViewSettingsGroup));
    settings.remove(QString());
    for (const ProcessCustomView& customView : m_customViews)
    {
        QStringList columnTexts;
        columnTexts.reserve(static_cast<int>(customView.visibleColumns.size()));
        for (const int columnIndex : customView.visibleColumns)
        {
            columnTexts.push_back(QString::number(columnIndex));
        }
        settings.setValue(customView.name, columnTexts.join(QChar(',')));
    }
    settings.endGroup();
}

void ProcessDock::rebuildViewModeComboItems()
{
    if (m_viewModeCombo == nullptr)
    {
        return;
    }

    // 记住当前选中项，重建后尽量恢复到同一个视图。
    const int previousDataValue = m_viewModeCombo->count() > 0
        ? m_viewModeCombo->currentData().toInt()
        : 0;

    // 重建期间屏蔽 currentIndexChanged：否则每加一项都会触发一次视图切换与强制刷新。
    m_viewModeComboUpdating = true;
    m_viewModeCombo->clear();

    for (int modeIndex = 0; modeIndex < static_cast<int>(ViewMode::Count); ++modeIndex)
    {
        const ViewMode viewMode = static_cast<ViewMode>(modeIndex);
        const QIcon itemIcon(QString::fromLatin1(
            viewMode == ViewMode::Monitor ? ProcessViewMonitorIconPath : ProcessViewPresetIconPath));
        m_viewModeCombo->addItem(itemIcon, viewModeDisplayName(viewMode));
        m_viewModeCombo->setItemData(m_viewModeCombo->count() - 1, modeIndex);
    }

    for (std::size_t customIndex = 0; customIndex < m_customViews.size(); ++customIndex)
    {
        // 自定义视图统一加前缀，避免与内置预设重名时无法分辨。
        m_viewModeCombo->addItem(
            ks::i18n::contextText(
                QStringLiteral("process.view.custom_prefix"),
                QStringLiteral("自定义：%1"))
                .arg(m_customViews[customIndex].name));
        m_viewModeCombo->setItemData(
            m_viewModeCombo->count() - 1,
            -static_cast<int>(customIndex) - 1);
    }

    int restoredIndex = m_viewModeCombo->findData(previousDataValue);
    if (restoredIndex < 0)
    {
        restoredIndex = 0;
    }
    m_viewModeCombo->setCurrentIndex(restoredIndex);
    m_viewModeComboUpdating = false;
}

int ProcessDock::saveCurrentColumnsAsCustomView(const QString& viewName)
{
    const QString trimmedName = viewName.trimmed();
    if (m_processTable == nullptr || trimmedName.isEmpty())
    {
        return -1;
    }

    ProcessCustomView customView;
    customView.name = trimmedName;
    for (int columnIndex = 0; columnIndex < static_cast<int>(TableColumn::Count); ++columnIndex)
    {
        if (!m_processTable->isColumnHidden(columnIndex))
        {
            customView.visibleColumns.push_back(columnIndex);
        }
    }
    if (customView.visibleColumns.empty())
    {
        return -1;
    }

    // 同名视图直接覆盖，符合“另存为同名即更新”的直觉。
    int targetIndex = -1;
    for (std::size_t existingIndex = 0; existingIndex < m_customViews.size(); ++existingIndex)
    {
        if (m_customViews[existingIndex].name.compare(trimmedName, Qt::CaseInsensitive) == 0)
        {
            targetIndex = static_cast<int>(existingIndex);
            break;
        }
    }
    if (targetIndex >= 0)
    {
        m_customViews[static_cast<std::size_t>(targetIndex)] = std::move(customView);
    }
    else
    {
        m_customViews.push_back(std::move(customView));
        targetIndex = static_cast<int>(m_customViews.size()) - 1;
    }

    saveCustomViewsToSettings();
    rebuildViewModeComboItems();

    // 选中刚保存的视图，让用户立刻看到它已经生效。
    if (m_viewModeCombo != nullptr)
    {
        const int itemIndex = m_viewModeCombo->findData(-targetIndex - 1);
        if (itemIndex >= 0)
        {
            m_viewModeComboUpdating = true;
            m_viewModeCombo->setCurrentIndex(itemIndex);
            m_viewModeComboUpdating = false;
        }
    }

    kLogEvent logEvent;
    info << logEvent
        << "[ProcessDock] 已保存自定义视图, name=" << trimmedName.toStdString()
        << ", columnCount=" << m_customViews[static_cast<std::size_t>(targetIndex)].visibleColumns.size()
        << eol;
    return targetIndex;
}

void ProcessDock::removeCustomView(const int customIndex)
{
    if (customIndex < 0 || customIndex >= static_cast<int>(m_customViews.size()))
    {
        return;
    }

    const QString removedName = m_customViews[static_cast<std::size_t>(customIndex)].name;
    m_customViews.erase(m_customViews.begin() + customIndex);
    saveCustomViewsToSettings();
    rebuildViewModeComboItems();

    // 删除后回落到监视视图，避免下拉停留在已经不存在的项上。
    if (m_viewModeCombo != nullptr)
    {
        const int monitorItemIndex = m_viewModeCombo->findData(static_cast<int>(ViewMode::Monitor));
        if (monitorItemIndex >= 0)
        {
            m_viewModeCombo->setCurrentIndex(monitorItemIndex);
        }
    }

    kLogEvent logEvent;
    info << logEvent
        << "[ProcessDock] 已删除自定义视图, name=" << removedName.toStdString()
        << eol;
}

std::uint32_t ProcessDock::currentProcessDetailDemandFlags() const
{
    // 输入：进程表当前的列显隐状态。
    // 处理：把“需要额外查询才能填充的列”映射为采集需求位。
    // 返回：ks::process::ProcessDetailDemand 位图；默认列布局下为 None。
    if (m_processTable == nullptr)
    {
        return ks::process::ProcessDetailDemand::None;
    }

    std::uint32_t demandFlags = ks::process::ProcessDetailDemand::None;

    if (isProcessColumnVisible(TableColumn::GdiObjects) ||
        isProcessColumnVisible(TableColumn::UserObjects))
    {
        demandFlags |= ks::process::ProcessDetailDemand::GuiResources;
    }
    if (isProcessColumnVisible(TableColumn::JobObject))
    {
        demandFlags |= ks::process::ProcessDetailDemand::JobObject;
    }
    if (isProcessColumnVisible(TableColumn::DataExecutionPrevention) ||
        isProcessColumnVisible(TableColumn::ControlFlowGuard) ||
        isProcessColumnVisible(TableColumn::HardwareStackProtection))
    {
        demandFlags |= ks::process::ProcessDetailDemand::MitigationPolicy;
    }
    if (isProcessColumnVisible(TableColumn::PackageName))
    {
        demandFlags |= ks::process::ProcessDetailDemand::PackageName;
    }
    if (isProcessColumnVisible(TableColumn::DpiAwareness))
    {
        demandFlags |= ks::process::ProcessDetailDemand::DpiAwareness;
    }
    if (isProcessColumnVisible(TableColumn::UacVirtualization))
    {
        demandFlags |= ks::process::ProcessDetailDemand::UacVirtualization;
    }
    if (isProcessColumnVisible(TableColumn::Description))
    {
        demandFlags |= ks::process::ProcessDetailDemand::FileDescription;
    }
    if (isProcessColumnVisible(TableColumn::OsContext))
    {
        demandFlags |= ks::process::ProcessDetailDemand::OsContext;
    }
    if (isProcessColumnVisible(TableColumn::EnterpriseContext))
    {
        demandFlags |= ks::process::ProcessDetailDemand::EnterpriseContext;
    }
    if (isProcessColumnVisible(TableColumn::GpuDedicatedMemory) ||
        isProcessColumnVisible(TableColumn::GpuSharedMemory))
    {
        demandFlags |= ks::process::ProcessDetailDemand::GpuMemory;
    }
    if (isProcessColumnVisible(TableColumn::GpuEngine))
    {
        demandFlags |= ks::process::ProcessDetailDemand::GpuEngine;
    }

    return demandFlags;
}

void ProcessDock::showColumnChooserDialog()
{
    if (m_processTable == nullptr)
    {
        return;
    }

    QDialog columnDialog(this);
    columnDialog.setObjectName(QStringLiteral("ProcessColumnChooserDialog"));
    columnDialog.setWindowTitle(
        processColumnChooserText("process.columns.dialog.title", QStringLiteral("选择列")));
    columnDialog.setMinimumSize(460, 560);
    // 使用不透明对话框样式：进程页可能开启毛玻璃背景，透明面板会让长列表难以辨认。
    columnDialog.setStyleSheet(KswordTheme::OpaqueDialogStyle(columnDialog.objectName()));

    auto* const dialogLayout = new QVBoxLayout(&columnDialog);
    dialogLayout->setContentsMargins(12, 12, 12, 12);
    dialogLayout->setSpacing(8);

    auto* const hintLabel = new QLabel(
        processColumnChooserText(
            "process.columns.dialog.hint",
            QStringLiteral("勾选需要在进程列表中显示的列。部分列需要额外查询，只有勾选后才会采集。")),
        &columnDialog);
    hintLabel->setWordWrap(true);
    dialogLayout->addWidget(hintLabel);

    auto* const searchEdit = new QLineEdit(&columnDialog);
    searchEdit->setClearButtonEnabled(true);
    searchEdit->setPlaceholderText(
        processColumnChooserText("process.columns.dialog.search", QStringLiteral("搜索列名...")));
    dialogLayout->addWidget(searchEdit);

    auto* const scrollArea = new QScrollArea(&columnDialog);
    scrollArea->setWidgetResizable(true);
    auto* const scrollContent = new QWidget(scrollArea);
    auto* const scrollLayout = new QVBoxLayout(scrollContent);
    scrollLayout->setContentsMargins(4, 4, 4, 4);
    scrollLayout->setSpacing(4);

    // columnCheckBoxes：按列索引保存复选框，便于搜索过滤与批量勾选。
    std::vector<QCheckBox*> columnCheckBoxes(static_cast<std::size_t>(TableColumn::Count), nullptr);
    // groupLabels：分组标题控件，用于在搜索时隐藏没有命中项的整组。
    std::vector<QLabel*> groupLabels(static_cast<std::size_t>(ProcessColumnGroup::Count), nullptr);

    for (int groupIndex = 0; groupIndex < static_cast<int>(ProcessColumnGroup::Count); ++groupIndex)
    {
        const ProcessColumnGroup group = static_cast<ProcessColumnGroup>(groupIndex);

        auto* const groupLabel = new QLabel(processColumnGroupTitle(group), scrollContent);
        groupLabel->setStyleSheet(QStringLiteral("font-weight:700;color:%1;padding-top:6px;")
            .arg(KswordTheme::PrimaryBlueHex));
        scrollLayout->addWidget(groupLabel);
        groupLabels[static_cast<std::size_t>(groupIndex)] = groupLabel;

        for (int columnIndex = 0; columnIndex < static_cast<int>(TableColumn::Count); ++columnIndex)
        {
            const TableColumn column = static_cast<TableColumn>(columnIndex);
            if (processColumnGroupOf(column) != group)
            {
                continue;
            }

            const QString columnName = processColumnDisplayName(columnIndex);
            if (columnName.isEmpty())
            {
                continue;
            }

            auto* const columnCheck = new QCheckBox(columnName, scrollContent);
            columnCheck->setChecked(!m_processTable->isColumnHidden(columnIndex));
            columnCheck->setProperty("kswordColumnIndex", columnIndex);

            // 名称列是行标识，不允许整列隐藏，否则列表将无法辨认进程。
            if (column == TableColumn::Name)
            {
                columnCheck->setChecked(true);
                columnCheck->setEnabled(false);
                columnCheck->setToolTip(processColumnChooserText(
                    "process.columns.dialog.name_locked",
                    QStringLiteral("进程名列是行标识，不能隐藏。")));
            }

            scrollLayout->addWidget(columnCheck);
            columnCheckBoxes[static_cast<std::size_t>(columnIndex)] = columnCheck;
        }
    }

    scrollLayout->addStretch(1);
    scrollArea->setWidget(scrollContent);
    dialogLayout->addWidget(scrollArea, 1);

    auto* const quickActionLayout = new QHBoxLayout();
    quickActionLayout->setSpacing(6);
    auto* const selectAllButton = new QPushButton(
        processColumnChooserText("process.columns.dialog.select_all", QStringLiteral("全选")),
        &columnDialog);
    auto* const clearAllButton = new QPushButton(
        processColumnChooserText("process.columns.dialog.clear_all", QStringLiteral("全不选")),
        &columnDialog);
    auto* const restoreDefaultButton = new QPushButton(
        processColumnChooserText("process.columns.dialog.restore_default", QStringLiteral("恢复默认")),
        &columnDialog);
    auto* const saveViewButton = new QPushButton(
        processColumnChooserText("process.columns.dialog.save_view", QStringLiteral("保存为视图...")),
        &columnDialog);
    auto* const deleteViewButton = new QPushButton(
        processColumnChooserText("process.columns.dialog.delete_view", QStringLiteral("删除当前视图")),
        &columnDialog);
    // 只有当前选中的就是自定义视图时才允许删除，内置预设不可删除。
    deleteViewButton->setEnabled(currentCustomViewIndex() >= 0);
    quickActionLayout->addWidget(selectAllButton);
    quickActionLayout->addWidget(clearAllButton);
    quickActionLayout->addWidget(restoreDefaultButton);
    quickActionLayout->addWidget(saveViewButton);
    quickActionLayout->addWidget(deleteViewButton);
    quickActionLayout->addStretch(1);
    dialogLayout->addLayout(quickActionLayout);

    auto* const buttonBox = new QDialogButtonBox(
        QDialogButtonBox::Ok | QDialogButtonBox::Cancel,
        &columnDialog);
    dialogLayout->addWidget(buttonBox);

    // 搜索过滤：命中列名的项保留，整组无命中时连标题一起隐藏。
    QObject::connect(searchEdit, &QLineEdit::textChanged, &columnDialog,
        [&columnCheckBoxes, &groupLabels](const QString& filterText)
        {
            const QString normalizedFilter = filterText.trimmed();
            std::vector<bool> groupHasVisibleItem(
                static_cast<std::size_t>(ProcessColumnGroup::Count),
                false);

            for (std::size_t columnIndex = 0; columnIndex < columnCheckBoxes.size(); ++columnIndex)
            {
                QCheckBox* const columnCheck = columnCheckBoxes[columnIndex];
                if (columnCheck == nullptr)
                {
                    continue;
                }

                const bool matched = normalizedFilter.isEmpty() ||
                    columnCheck->text().contains(normalizedFilter, Qt::CaseInsensitive);
                columnCheck->setVisible(matched);
                if (matched)
                {
                    const ProcessColumnGroup group =
                        processColumnGroupOf(static_cast<TableColumn>(columnIndex));
                    groupHasVisibleItem[static_cast<std::size_t>(group)] = true;
                }
            }

            for (std::size_t groupIndex = 0; groupIndex < groupLabels.size(); ++groupIndex)
            {
                if (groupLabels[groupIndex] != nullptr)
                {
                    groupLabels[groupIndex]->setVisible(groupHasVisibleItem[groupIndex]);
                }
            }
        });

    // 全选 / 全不选只作用于当前搜索结果中可见的项，符合用户对筛选结果的直觉。
    const auto applyBulkCheckState =
        [&columnCheckBoxes](const bool checkedState) -> void
        {
            for (QCheckBox* const columnCheck : columnCheckBoxes)
            {
                if (columnCheck == nullptr || !columnCheck->isVisibleTo(columnCheck->parentWidget()))
                {
                    continue;
                }
                if (!columnCheck->isEnabled())
                {
                    continue;
                }
                columnCheck->setChecked(checkedState);
            }
        };
    QObject::connect(selectAllButton, &QPushButton::clicked, &columnDialog,
        [applyBulkCheckState]() { applyBulkCheckState(true); });
    QObject::connect(clearAllButton, &QPushButton::clicked, &columnDialog,
        [applyBulkCheckState]() { applyBulkCheckState(false); });

    // 恢复默认：先清空用户覆盖并重新套用视图预设，再按结果回填对话框勾选状态。
    QObject::connect(restoreDefaultButton, &QPushButton::clicked, &columnDialog,
        [this, &columnCheckBoxes]()
        {
            resetProcessColumnsToViewDefault();
            for (std::size_t columnIndex = 0; columnIndex < columnCheckBoxes.size(); ++columnIndex)
            {
                QCheckBox* const columnCheck = columnCheckBoxes[columnIndex];
                if (columnCheck == nullptr)
                {
                    continue;
                }
                const QSignalBlocker checkBlocker(columnCheck);
                columnCheck->setChecked(!m_processTable->isColumnHidden(static_cast<int>(columnIndex)));
            }
        });

    // applyCheckedColumnsToTable：把对话框里的勾选状态写入表格，返回实际变更的列数。
    // 逐列写入时不立即持久化，由调用方在批量结束后统一保存并只做一次刷新判定。
    const auto applyCheckedColumnsToTable =
        [this, &columnCheckBoxes]() -> int
        {
            int changedCount = 0;
            for (std::size_t columnIndex = 0; columnIndex < columnCheckBoxes.size(); ++columnIndex)
            {
                QCheckBox* const columnCheck = columnCheckBoxes[columnIndex];
                if (columnCheck == nullptr)
                {
                    continue;
                }

                const int targetColumn = static_cast<int>(columnIndex);
                const bool shouldShow = columnCheck->isChecked();
                if (shouldShow == !m_processTable->isColumnHidden(targetColumn))
                {
                    continue;
                }
                setProcessColumnVisible(targetColumn, shouldShow, false);
                ++changedCount;
            }
            return changedCount;
        };

    // commitColumnLayoutChanges：保存列布局并在采集需求变化时立即强制刷新一轮。
    const auto commitColumnLayoutChanges =
        [this]() -> void
        {
            saveProcessColumnLayoutToSettings();
            applyAdaptiveColumnWidths();

            const std::uint32_t nextDemandFlags = currentProcessDetailDemandFlags();
            if (nextDemandFlags != m_lastProcessDetailDemandFlags)
            {
                m_lastProcessDetailDemandFlags = nextDemandFlags;
            }
            // 批量列变更也可能包含 CPU核心，其 ETW 生命周期不属于 ProcessDetailDemand 位图。
            // 对话框只在实际列变化后调用本提交函数，因此统一强制刷新一次不会形成周期额外负担。
            requestAsyncRefresh(true);
        };

    // 保存为视图：先把当前勾选落到表格，再以该组合创建/覆盖同名自定义视图。
    QObject::connect(saveViewButton, &QPushButton::clicked, &columnDialog,
        [this, &columnDialog, applyCheckedColumnsToTable, commitColumnLayoutChanges]()
        {
            bool inputOk = false;
            const QString viewName = QInputDialog::getText(
                &columnDialog,
                processColumnChooserText("process.columns.dialog.save_view_title", QStringLiteral("保存为视图")),
                processColumnChooserText("process.columns.dialog.save_view_prompt", QStringLiteral("视图名称：")),
                QLineEdit::Normal,
                QString(),
                &inputOk);
            if (!inputOk || viewName.trimmed().isEmpty())
            {
                return;
            }

            applyCheckedColumnsToTable();
            commitColumnLayoutChanges();
            saveCurrentColumnsAsCustomView(viewName);
            columnDialog.accept();
        });

    // 删除当前自定义视图：删除后视图下拉会回落到监视视图。
    QObject::connect(deleteViewButton, &QPushButton::clicked, &columnDialog,
        [this, &columnDialog]()
        {
            const int customIndex = currentCustomViewIndex();
            if (customIndex < 0)
            {
                return;
            }
            removeCustomView(customIndex);
            columnDialog.reject();
        });

    QObject::connect(buttonBox, &QDialogButtonBox::accepted, &columnDialog, &QDialog::accept);
    QObject::connect(buttonBox, &QDialogButtonBox::rejected, &columnDialog, &QDialog::reject);

    if (columnDialog.exec() != QDialog::Accepted)
    {
        return;
    }

    // 批量应用：逐列写入覆盖但不立即持久化，最后统一保存并只做一次刷新判定。
    // “保存为视图”分支已经提交过一次，这里的 changedColumnCount 会是 0 并直接返回。
    const int changedColumnCount = applyCheckedColumnsToTable();
    if (changedColumnCount == 0)
    {
        return;
    }

    commitColumnLayoutChanges();

    kLogEvent logEvent;
    info << logEvent
        << "[ProcessDock] 选择列已应用, changedColumnCount=" << changedColumnCount
        << ", demandFlags=" << m_lastProcessDetailDemandFlags
        << eol;
}
