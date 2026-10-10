
#include "KernelDeviceDriverObjectsTab.h"
#include "../UI/PageControlStyle.h"
#include "../UI/ToolbarMetrics.h"
#include "KernelDriverDispatchEditorDialog.h"
#include "KernelDriverImageEditorDialog.h"
#include "KernelDock.h"
#include "../UI/TableInteractionSupport.h"
#include "../UI/VisibleTableWidget.h"

// ============================================================
// KernelDeviceDriverObjectsTab.cpp
// 作用说明：
// 1) 构建“设备与驱动”专项视图 UI；
// 2) 后台异步触发 R3 枚举任务，避免阻塞界面；
// 3) 提供目录/类型/关键字过滤、复制与 TSV 导出。
// ============================================================

#include "../theme.h"

#include <QAction>
#include <QAbstractItemView>
#include <QApplication>
#include <QClipboard>
#include <QComboBox>
#include <QFile>
#include <QFileDialog>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMessageBox>
#include <QMetaObject>
#include <QPointer>
#include <QPushButton>
#include <QSignalBlocker>
#include <QSizePolicy>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QStringList>
#include <QTimer>
#include <QVBoxLayout>

#include <algorithm> // std::find/std::sort/std::unique：筛选与排序。
#include <utility>   // std::move：移动后台结果。
#include <thread>    // std::thread：后台枚举线程。

using ksword::kernel_dock_internal::kernelText;

namespace
{
    // ============================================================
    // 目录规格：
    // - 与 worker 里的枚举目录保持一致；
    // - 这里只负责 UI 下拉框显示，不承载任何枚举逻辑。
    // ============================================================
    struct RootDirectorySpec
    {
        QString pathText;      // pathText：对象管理器目录路径。
        QString displayText;   // displayText：下拉框显示文本。
    };

    // kRootDirectorySpecs：
    // - 作用：为过滤器提供固定目录选项；
    // - 返回：静态数组，顺序固定且只读。
    const std::vector<RootDirectorySpec> kRootDirectorySpecs{
        { QStringLiteral("\\Device"), QStringLiteral("\\Device") },
        { QStringLiteral("\\Driver"), QStringLiteral("\\Driver") },
        { QStringLiteral("\\FileSystem"), QStringLiteral("\\FileSystem") },
        { QStringLiteral("\\FileSystem\\Filters"), QStringLiteral("\\FileSystem\\Filters") },
    };

    // blueButtonStyle：
    // - 作用：生成统一主按钮样式；
    // - 返回：可直接用于 setStyleSheet 的样式文本。
    QString blueButtonStyle()
    {
        return KswordTheme::ThemedButtonStyle();
    }

    // blueInputStyle：
    // - 作用：生成统一输入框样式；
    // - 返回：可直接用于 setStyleSheet 的样式文本。
    QString blueInputStyle()
    {
        return QStringLiteral(
            "QLineEdit{border:1px solid %2;border-radius:2px;background:transparent;/* %3 */color:%4;padding:2px 6px;}"
            "QLineEdit:focus{border:1px solid %1;}")
            .arg(KswordTheme::PrimaryBlueHex)
            .arg(KswordTheme::BorderHex())
            .arg(KswordTheme::SurfaceHex())
            .arg(KswordTheme::TextPrimaryHex());
    }

    // headerStyle：
    // - 作用：生成表头样式；
    // - 返回：可直接用于 horizontalHeader()->setStyleSheet 的文本。
    QString headerStyle()
    {
        return QStringLiteral(
            "QHeaderView::section{color:%1;background:transparent;/* %2 */border:1px solid %3;font-weight:600;}")
            .arg(KswordTheme::PrimaryBlueHex)
            .arg(KswordTheme::SurfaceHex())
            .arg(KswordTheme::BorderHex());
    }

    // statusLabelStyle：
    // - 作用：生成状态标签颜色样式；
    // - 返回：可直接用于 setStyleSheet 的文本。
    QString statusLabelStyle(const QString& colorHex)
    {
        return QStringLiteral("color:%1;font-weight:600;").arg(colorHex);
    }

    // makeLabel：
    // - 输入 text：标签文本；
    // - 处理：创建说明标签并统一主题；
    // - 返回：可直接加入布局的 QLabel。
    QLabel* makeLabel(const QString& text, QWidget* parentWidget)
    {
        auto* label = new QLabel(text, parentWidget);
        label->setStyleSheet(statusLabelStyle(KswordTheme::TextSecondaryHex()));
        return label;
    }

    // setColumnWidthIfPresent：
    // - 输入 table、column、width；
    // - 处理：仅在列存在时设置宽度，便于复用；
    // - 返回：无返回值。
    void setColumnWidthIfPresent(QTableWidget* table, const int column, const int width)
    {
        if (table != nullptr && column >= 0 && column < table->columnCount())
        {
            table->setColumnWidth(column, width);
        }
    }
}

// KernelDeviceDriverObjectsTab：
// - 输入 parent：Qt 父控件；
// - 处理：搭建 UI 并触发首次异步刷新；
// - 返回：无返回值。
KernelDeviceDriverObjectsTab::KernelDeviceDriverObjectsTab(QWidget* parent)
    : QWidget(parent)
{
    initializeUi();
    initializeConnections();

    // 首次打开时延迟触发刷新，避免构造阶段阻塞 UI。
    QTimer::singleShot(0, this, [this]() {
        refreshAsync();
    });
}

// initializeUi：
// - 处理：构建顶部工具条、过滤器和结果表；
// - 返回：无返回值。
void KernelDeviceDriverObjectsTab::initializeUi()
{
    m_rootLayout = new QVBoxLayout(this);
    m_rootLayout->setContentsMargins(6, 6, 6, 6);
    m_rootLayout->setSpacing(4);

    m_toolbarWidget = new QWidget(this);
    auto* toolbarLayout = new QHBoxLayout(m_toolbarWidget);
    toolbarLayout->setContentsMargins(0, 0, 0, 0);
    toolbarLayout->setSpacing(6);

    m_refreshButton = new QPushButton(kernelText("kernel.device_driver.toolbar.refresh", QStringLiteral("刷新")), m_toolbarWidget);
    m_refreshButton->setStyleSheet(blueButtonStyle());
    m_refreshButton->setToolTip(kernelText("kernel.device_driver.toolbar.refresh.tooltip", QStringLiteral("重新枚举 \\Device、\\Driver、\\FileSystem 等对象目录")));
    m_exportButton = new QPushButton(kernelText("kernel.device_driver.toolbar.export", QStringLiteral("导出 TSV")), m_toolbarWidget);
    m_exportButton->setStyleSheet(blueButtonStyle());
    m_exportButton->setToolTip(kernelText("kernel.device_driver.toolbar.export.tooltip", QStringLiteral("把当前可见结果导出为 TSV")));
    m_statusLabel = new QLabel(kernelText("kernel.device_driver.status.initial", QStringLiteral("状态：首次打开后正在加载设备与驱动对象...")), m_toolbarWidget);
    m_statusLabel->setStyleSheet(statusLabelStyle(KswordTheme::TextSecondaryHex()));
    m_statusLabel->setWordWrap(true);
    m_statusLabel->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);

    toolbarLayout->addWidget(m_refreshButton, 0);
    toolbarLayout->addWidget(m_exportButton, 0);
    toolbarLayout->addWidget(m_statusLabel, 1);
    ks::ui::NormalizeToolbarRow(toolbarLayout);
    m_rootLayout->addWidget(m_toolbarWidget, 0);

    m_filterWidget = new QWidget(this);
    auto* filterLayout = new QHBoxLayout(m_filterWidget);
    filterLayout->setContentsMargins(0, 0, 0, 0);
    filterLayout->setSpacing(6);

    m_directoryFilterCombo = new QComboBox(m_filterWidget);
    m_directoryFilterCombo->setEditable(false);
    m_directoryFilterCombo->setMinimumWidth(190);
    m_directoryFilterCombo->setToolTip(kernelText("kernel.device_driver.filter.directory.tooltip", QStringLiteral("按对象目录过滤")));
    m_typeFilterCombo = new QComboBox(m_filterWidget);
    m_typeFilterCombo->setEditable(false);
    m_typeFilterCombo->setMinimumWidth(160);
    m_typeFilterCombo->setToolTip(kernelText("kernel.device_driver.filter.type.tooltip", QStringLiteral("按对象类型过滤")));
    m_keywordEdit = new QLineEdit(m_filterWidget);
    m_keywordEdit->setPlaceholderText(kernelText("kernel.device_driver.filter.keyword.placeholder", QStringLiteral("关键字过滤：名称 / 类型 / 路径 / 目标 / 提示")));
    m_keywordEdit->setClearButtonEnabled(true);
    ks::ui::StyleSearchField(m_keywordEdit);

    filterLayout->addWidget(makeLabel(kernelText("kernel.device_driver.filter.directory.label", QStringLiteral("目录：")), m_filterWidget), 0);
    filterLayout->addWidget(m_directoryFilterCombo, 0);
    filterLayout->addWidget(makeLabel(kernelText("kernel.device_driver.filter.type.label", QStringLiteral("类型：")), m_filterWidget), 0);
    filterLayout->addWidget(m_typeFilterCombo, 0);
    filterLayout->addWidget(makeLabel(kernelText("kernel.device_driver.filter.keyword.label", QStringLiteral("关键字：")), m_filterWidget), 0);
    filterLayout->addWidget(m_keywordEdit, 1);
    ks::ui::NormalizeToolbarRow(filterLayout);
    m_rootLayout->addWidget(m_filterWidget, 0);

    m_tableWidget = new ks::ui::VisibleTableWidget(this);
    // 设备/驱动对象清单需要捕获新增与消失对象，保留现场对比。
    ks::ui::SetTableActionBarMode(m_tableWidget, ks::ui::TableActionBarMode::Full);
    m_tableWidget->setColumnCount(7);
    m_tableWidget->setHorizontalHeaderLabels({
        kernelText("kernel.device_driver.header.directory", QStringLiteral("目录路径")),
        kernelText("kernel.device_driver.header.object_name", QStringLiteral("对象名称")),
        kernelText("kernel.device_driver.header.object_type", QStringLiteral("对象类型")),
        kernelText("kernel.device_driver.header.full_path", QStringLiteral("完整路径")),
        kernelText("kernel.device_driver.header.target_path", QStringLiteral("目标路径")),
        kernelText("kernel.device_driver.header.status", QStringLiteral("状态")),
        kernelText("kernel.device_driver.header.capability", QStringLiteral("能力提示")),
    });
    m_tableWidget->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_tableWidget->setSelectionMode(QAbstractItemView::SingleSelection);
    m_tableWidget->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_tableWidget->setContextMenuPolicy(Qt::CustomContextMenu);
    m_tableWidget->setAlternatingRowColors(true);
    m_tableWidget->setWordWrap(false);
    m_tableWidget->verticalHeader()->setVisible(false);
    m_tableWidget->horizontalHeader()->setStyleSheet(headerStyle());
    m_tableWidget->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
    m_tableWidget->horizontalHeader()->setStretchLastSection(true);
    setColumnWidthIfPresent(m_tableWidget, 0, 190);
    setColumnWidthIfPresent(m_tableWidget, 1, 180);
    setColumnWidthIfPresent(m_tableWidget, 2, 130);
    setColumnWidthIfPresent(m_tableWidget, 3, 320);
    setColumnWidthIfPresent(m_tableWidget, 4, 320);
    setColumnWidthIfPresent(m_tableWidget, 5, 260);
    m_rootLayout->addWidget(m_tableWidget, 1);
}

// initializeConnections：
// - 处理：连接刷新、导出、过滤和右键菜单行为；
// - 返回：无返回值。
void KernelDeviceDriverObjectsTab::initializeConnections()
{
    connect(m_refreshButton, &QPushButton::clicked, this, [this]() {
        refreshAsync();
    });

    connect(m_exportButton, &QPushButton::clicked, this, [this]() {
        exportVisibleRowsAsTsv();
    });

    connect(m_directoryFilterCombo, &QComboBox::currentTextChanged, this, [this](const QString&) {
        rebuildVisibleRows();
    });

    connect(m_typeFilterCombo, &QComboBox::currentTextChanged, this, [this](const QString&) {
        rebuildVisibleRows();
    });

    connect(m_keywordEdit, &QLineEdit::textChanged, this, [this](const QString&) {
        rebuildVisibleRows();
    });

    connect(m_tableWidget, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& localPosition) {
        showTableContextMenu(localPosition);
    });
}

// refreshAsync：
// - 处理：后台执行对象目录枚举，完成后回投 UI；
// - 返回：无返回值。
void KernelDeviceDriverObjectsTab::refreshAsync()
{
    if (m_refreshRunning.exchange(true))
    {
        if (m_statusLabel != nullptr)
        {
            m_statusLabel->setText(kernelText("kernel.device_driver.status.already_refreshing", QStringLiteral("状态：刷新进行中，重复请求已忽略。")));
            m_statusLabel->setStyleSheet(statusLabelStyle(KswordTheme::PrimaryBlueHex));
        }
        return;
    }

    if (m_refreshButton != nullptr)
    {
        m_refreshButton->setEnabled(false);
    }
    updateStatusText();

    QPointer<KernelDeviceDriverObjectsTab> guardThis(this);
    std::thread([guardThis]() {
        std::vector<KernelDeviceDriverObjectEntry> resultRows;
        QString errorText;
        const bool success = runKernelDeviceDriverObjectsSnapshotTask(resultRows, errorText);

        KernelDeviceDriverObjectsTab* const contextObject = guardThis.data();
        if (contextObject == nullptr)
        {
            return;
        }

        QMetaObject::invokeMethod(contextObject, [guardThis, success, errorText, resultRows = std::move(resultRows)]() mutable {
            if (guardThis == nullptr)
            {
                return;
            }

            guardThis->m_refreshRunning.store(false);
            if (guardThis->m_refreshButton != nullptr)
            {
                guardThis->m_refreshButton->setEnabled(true);
            }

            if (!success)
            {
                guardThis->applyRefreshResult(std::vector<KernelDeviceDriverObjectEntry>(), errorText);
                return;
            }

            guardThis->applyRefreshResult(std::move(resultRows), QString());
        }, Qt::QueuedConnection);
    }).detach();
}

// applyRefreshResult：
// - 输入 rows：后台枚举结果；input errorText：致命错误文本；
// - 处理：刷新缓存、过滤器和表格；
// - 返回：无返回值。
void KernelDeviceDriverObjectsTab::applyRefreshResult(
    std::vector<KernelDeviceDriverObjectEntry> rows,
    const QString& errorText)
{
    const QPointer<KernelDeviceDriverObjectsTab> safeThis(this);
    if (ks::ui::DeferTableUiCommitIfContextMenuOpen(
        this,
        QStringLiteral("kernel-device-driver-objects-snapshot"),
        { m_tableWidget },
        [safeThis, rows, errorText]() mutable
        {
            if (!safeThis.isNull())
            {
                safeThis->applyRefreshResult(std::move(rows), errorText);
            }
        }))
    {
        return;
    }

    if (!errorText.isEmpty())
    {
        updateStatusText(errorText);
        return;
    }

    m_allRows = std::move(rows);
    populateFilterCombos(m_allRows);
    rebuildVisibleRows();
}

// populateFilterCombos：
// - 输入 rows：当前全量枚举结果；
// - 处理：重新填充目录和类型下拉框，保留当前选择能保留的值；
// - 返回：无返回值。
void KernelDeviceDriverObjectsTab::populateFilterCombos(const std::vector<KernelDeviceDriverObjectEntry>& rows)
{
    const QString currentDirectoryText = m_directoryFilterCombo != nullptr ? m_directoryFilterCombo->currentText() : QString();
    const QString currentTypeText = m_typeFilterCombo != nullptr ? m_typeFilterCombo->currentText() : QString();

    if (m_directoryFilterCombo != nullptr)
    {
        QSignalBlocker blocker(m_directoryFilterCombo);
        m_directoryFilterCombo->clear();
        m_directoryFilterCombo->addItem(kernelText("kernel.device_driver.filter.all_directories", QStringLiteral("全部目录")), QStringLiteral("*"));
        for (const RootDirectorySpec& spec : kRootDirectorySpecs)
        {
            m_directoryFilterCombo->addItem(spec.displayText, spec.pathText);
        }

        const int matchIndex = m_directoryFilterCombo->findText(currentDirectoryText);
        m_directoryFilterCombo->setCurrentIndex(matchIndex >= 0 ? matchIndex : 0);
    }

    if (m_typeFilterCombo != nullptr)
    {
        QSignalBlocker blocker(m_typeFilterCombo);
        m_typeFilterCombo->clear();
        m_typeFilterCombo->addItem(kernelText("kernel.device_driver.filter.all_types", QStringLiteral("全部类型")), QStringLiteral("*"));

        QStringList uniqueTypes;
        uniqueTypes.reserve(static_cast<int>(rows.size()));
        for (const KernelDeviceDriverObjectEntry& entry : rows)
        {
            const QString typeText = entry.objectTypeText.trimmed();
            if (!typeText.isEmpty() && !uniqueTypes.contains(typeText, Qt::CaseInsensitive))
            {
                uniqueTypes.push_back(typeText);
            }
        }
        std::sort(uniqueTypes.begin(), uniqueTypes.end(), [](const QString& left, const QString& right) {
            return QString::compare(left, right, Qt::CaseInsensitive) < 0;
        });

        for (const QString& typeText : uniqueTypes)
        {
            m_typeFilterCombo->addItem(typeText, typeText);
        }

        const int matchIndex = m_typeFilterCombo->findText(currentTypeText);
        m_typeFilterCombo->setCurrentIndex(matchIndex >= 0 ? matchIndex : 0);
    }
}

// matchesCurrentFilters：
// - 输入 entry：待判断的一行；
// - 处理：按目录、类型和关键字做只读过滤；
// - 返回：true 表示该行应保留显示。
bool KernelDeviceDriverObjectsTab::matchesCurrentFilters(const KernelDeviceDriverObjectEntry& entry) const
{
    const QString directoryFilterText = m_directoryFilterCombo != nullptr
        ? m_directoryFilterCombo->currentData().toString().trimmed()
        : QString();
    const QString typeFilterText = m_typeFilterCombo != nullptr
        ? m_typeFilterCombo->currentData().toString().trimmed()
        : QString();
    const QString keywordText = m_keywordEdit != nullptr ? m_keywordEdit->text().trimmed() : QString();

    if (!directoryFilterText.isEmpty() && directoryFilterText != QStringLiteral("*"))
    {
        if (entry.directoryPathText.compare(directoryFilterText, Qt::CaseInsensitive) != 0)
        {
            return false;
        }
    }

    if (!typeFilterText.isEmpty() && typeFilterText != QStringLiteral("*"))
    {
        if (entry.objectTypeText.compare(typeFilterText, Qt::CaseInsensitive) != 0)
        {
            return false;
        }
    }

    if (!keywordText.isEmpty())
    {
        const auto containsKeyword = [&keywordText](const QString& textValue) {
            return textValue.contains(keywordText, Qt::CaseInsensitive);
        };

        if (!containsKeyword(entry.directoryPathText)
            && !containsKeyword(entry.objectNameText)
            && !containsKeyword(entry.objectTypeText)
            && !containsKeyword(entry.fullPathText)
            && !containsKeyword(entry.targetPathText)
            && !containsKeyword(entry.statusText)
            && !containsKeyword(entry.capabilityHintText)
            && !containsKeyword(entry.detailText))
        {
            return false;
        }
    }

    return true;
}

// rebuildVisibleRows：
// - 处理：根据当前过滤条件构建可见行并刷新表格；
// - 返回：无返回值。
void KernelDeviceDriverObjectsTab::rebuildVisibleRows()
{
    m_visibleRows.clear();
    for (const KernelDeviceDriverObjectEntry& entry : m_allRows)
    {
        if (matchesCurrentFilters(entry))
        {
            m_visibleRows.push_back(entry);
        }
    }

    rebuildTableWidget();
    updateStatusText();
}

// rebuildTableWidget：
// - 处理：把当前可见行填充进表格控件；
// - 返回：无返回值。
void KernelDeviceDriverObjectsTab::rebuildTableWidget()
{
    if (m_tableWidget == nullptr)
    {
        return;
    }

    m_tableWidget->setSortingEnabled(false);
    m_tableWidget->setUpdatesEnabled(false);
    m_tableWidget->clearContents();
    m_tableWidget->setRowCount(0);
    m_tableWidget->setRowCount(static_cast<int>(m_visibleRows.size()));

    for (int rowIndex = 0; rowIndex < static_cast<int>(m_visibleRows.size()); ++rowIndex)
    {
        const KernelDeviceDriverObjectEntry& entry = m_visibleRows[static_cast<std::size_t>(rowIndex)];
        const QString targetText = entry.targetPathText.isEmpty()
            ? kernelText("kernel.device_driver.placeholder.no_target", QStringLiteral("<无>"))
            : entry.targetPathText;

        m_tableWidget->setItem(rowIndex, 0, makeReadOnlyItem(entry.directoryPathText));
        m_tableWidget->setItem(rowIndex, 1, makeReadOnlyItem(entry.objectNameText));
        m_tableWidget->setItem(rowIndex, 2, makeReadOnlyItem(entry.objectTypeText));
        m_tableWidget->setItem(rowIndex, 3, makeReadOnlyItem(entry.fullPathText));
        m_tableWidget->setItem(rowIndex, 4, makeReadOnlyItem(targetText));
        m_tableWidget->setItem(rowIndex, 5, makeReadOnlyItem(entry.statusText));
        m_tableWidget->setItem(rowIndex, 6, makeReadOnlyItem(entry.capabilityHintText));
    }

    m_tableWidget->setUpdatesEnabled(true);
}

// updateStatusText：
// - 输入 errorText：可选错误说明；
// - 处理：按当前全量/可见数量与错误状态更新状态标签；
// - 返回：无返回值。
void KernelDeviceDriverObjectsTab::updateStatusText(const QString& errorText)
{
    if (m_statusLabel == nullptr)
    {
        return;
    }

    if (!errorText.isEmpty())
    {
        m_statusLabel->setText(kernelText("kernel.device_driver.status.failed", QStringLiteral("状态：刷新失败 - %1")).arg(errorText));
        m_statusLabel->setStyleSheet(statusLabelStyle(KswordTheme::ErrorHex()));
        return;
    }

    if (m_refreshRunning.load())
    {
        m_statusLabel->setText(kernelText("kernel.device_driver.status.refreshing", QStringLiteral("状态：刷新中...")));
        m_statusLabel->setStyleSheet(statusLabelStyle(KswordTheme::PrimaryBlueHex));
        return;
    }

    if (m_allRows.empty())
    {
        m_statusLabel->setText(kernelText("kernel.device_driver.status.no_results", QStringLiteral("状态：暂无结果，点击刷新开始枚举对象目录。")));
        m_statusLabel->setStyleSheet(statusLabelStyle(KswordTheme::TextSecondaryHex()));
        return;
    }

    if (m_visibleRows.empty())
    {
        m_statusLabel->setText(kernelText("kernel.device_driver.status.filter_empty", QStringLiteral("状态：已加载 %1 条，当前过滤后无可见结果。")).arg(m_allRows.size()));
        m_statusLabel->setStyleSheet(statusLabelStyle(KswordTheme::WarningHex()));
        return;
    }

    m_statusLabel->setText(
        kernelText("kernel.device_driver.status.summary", QStringLiteral("状态：已加载 %1 条，当前显示 %2 条。"))
        .arg(m_allRows.size())
        .arg(m_visibleRows.size()));
    m_statusLabel->setStyleSheet(statusLabelStyle(KswordTheme::SuccessHex()));
}

// showTableContextMenu：
// - 输入 localPosition：表格视口坐标；
// - 处理：根据点击单元格提供复制与导出操作；
// - 返回：无返回值。
void KernelDeviceDriverObjectsTab::showTableContextMenu(const QPoint& localPosition)
{
    if (m_tableWidget == nullptr)
    {
        return;
    }

    QTableWidgetItem* clickedItem = m_tableWidget->itemAt(localPosition);
    if (clickedItem != nullptr)
    {
        m_tableWidget->setCurrentItem(clickedItem);
    }

    const int row = clickedItem != nullptr ? clickedItem->row() : -1;
    const int column = clickedItem != nullptr ? clickedItem->column() : -1;

    QMenu menu(this);
    menu.setStyleSheet(KswordTheme::ContextMenuStyle());
    QAction* copyCellAction = menu.addAction(kernelText("kernel.device_driver.menu.copy_cell", QStringLiteral("复制单元格")));
    QAction* copyRowAction = menu.addAction(kernelText("kernel.device_driver.menu.copy_row", QStringLiteral("复制当前行")));
    QAction* copyTsvAction = menu.addAction(kernelText("kernel.device_driver.menu.copy_visible_tsv", QStringLiteral("复制可见结果 TSV")));
    QAction* exportAction = menu.addAction(kernelText("kernel.device_driver.menu.export_tsv", QStringLiteral("导出 TSV")));
    menu.addSeparator();
    QAction* dispatchEditorAction = menu.addAction(
        kernelText(
            "kernel.device_driver.menu.dispatch_editor",
            QStringLiteral("打开 IRP / MajorFunction 编辑器")));
    QAction* imageEditorAction = menu.addAction(
        kernelText(
            "kernel.device_driver.menu.image_editor",
            QStringLiteral("打开 DriverObject / KLDR 镜像编辑器")));

    const bool editableDriverObject = row >= 0 &&
        row < static_cast<int>(m_visibleRows.size()) &&
        !m_visibleRows[static_cast<std::size_t>(row)].isScopeEntry &&
        !m_visibleRows[static_cast<std::size_t>(row)].isDirectory &&
        (m_visibleRows[static_cast<std::size_t>(row)].fullPathText.startsWith(
            QStringLiteral("\\Driver\\"), Qt::CaseInsensitive) ||
         m_visibleRows[static_cast<std::size_t>(row)].fullPathText.startsWith(
            QStringLiteral("\\FileSystem\\"), Qt::CaseInsensitive));

    copyCellAction->setEnabled(row >= 0 && column >= 0);
    copyRowAction->setEnabled(row >= 0);
    copyTsvAction->setEnabled(!m_visibleRows.empty());
    exportAction->setEnabled(!m_visibleRows.empty());
    dispatchEditorAction->setEnabled(editableDriverObject);
    imageEditorAction->setEnabled(editableDriverObject);

    QAction* selectedAction = menu.exec(m_tableWidget->viewport()->mapToGlobal(localPosition));
    if (selectedAction == copyCellAction)
    {
        copyCellAt(row, column);
    }
    else if (selectedAction == copyRowAction)
    {
        copyRowAt(row);
    }
    else if (selectedAction == copyTsvAction)
    {
        copyVisibleRowsAsTsv();
    }
    else if (selectedAction == exportAction)
    {
        exportVisibleRowsAsTsv();
    }
    else if (selectedAction == dispatchEditorAction && editableDriverObject)
    {
        const KernelDeviceDriverObjectEntry& entry =
            m_visibleRows[static_cast<std::size_t>(row)];
        KernelDriverDispatchEditorDialog dialog(entry.fullPathText, this);
        dialog.exec();
    }
    else if (selectedAction == imageEditorAction && editableDriverObject)
    {
        const KernelDeviceDriverObjectEntry& entry =
            m_visibleRows[static_cast<std::size_t>(row)];
        KernelDriverImageEditorDialog dialog(entry.fullPathText, this);
        dialog.exec();
    }
}

// copyCellAt：
// - 输入 row / column：表格单元格位置；
// - 处理：把单元格文本写入系统剪贴板；
// - 返回：无返回值。
void KernelDeviceDriverObjectsTab::copyCellAt(const int row, const int column) const
{
    if (m_tableWidget == nullptr || row < 0 || column < 0)
    {
        return;
    }

    const QTableWidgetItem* item = m_tableWidget->item(row, column);
    if (QApplication::clipboard() != nullptr)
    {
        QApplication::clipboard()->setText(item != nullptr ? item->text() : QString());
    }
}

// copyRowAt：
// - 输入 row：目标行；
// - 处理：把整行按 TSV 规则写入剪贴板；
// - 返回：无返回值。
void KernelDeviceDriverObjectsTab::copyRowAt(const int row) const
{
    if (m_tableWidget == nullptr || row < 0)
    {
        return;
    }

    QStringList values;
    values.reserve(m_tableWidget->columnCount());
    for (int column = 0; column < m_tableWidget->columnCount(); ++column)
    {
        const QTableWidgetItem* item = m_tableWidget->item(row, column);
        values.push_back(sanitizeTsvField(item != nullptr ? item->text() : QString()));
    }

    if (QApplication::clipboard() != nullptr)
    {
        QApplication::clipboard()->setText(values.join(QStringLiteral("\t")));
    }
}

// copyVisibleRowsAsTsv：
// - 处理：把当前可见结果按 TSV 写入剪贴板；
// - 返回：无返回值。
void KernelDeviceDriverObjectsTab::copyVisibleRowsAsTsv() const
{
    if (QApplication::clipboard() != nullptr)
    {
        QApplication::clipboard()->setText(rowsToTsv(true));
    }
}

// exportVisibleRowsAsTsv：
// - 处理：把当前可见结果导出到用户选择的文件；
// - 返回：无返回值。
void KernelDeviceDriverObjectsTab::exportVisibleRowsAsTsv()
{
    if (m_visibleRows.empty())
    {
        QMessageBox::information(this, kernelText("kernel.device_driver.export.title", QStringLiteral("导出 TSV")), kernelText("kernel.device_driver.export.no_rows", QStringLiteral("当前没有可导出的可见结果。")));
        return;
    }

    const QString outputPath = QFileDialog::getSaveFileName(
        this,
        kernelText("kernel.device_driver.export.title", QStringLiteral("导出 TSV")),
        QStringLiteral("kernel_device_driver_objects.tsv"),
        kernelText("kernel.device_driver.export.file_filter", QStringLiteral("TSV 文件 (*.tsv)")));
    if (outputPath.isEmpty())
    {
        return;
    }

    QFile outputFile(outputPath);
    if (!outputFile.open(QIODevice::WriteOnly | QIODevice::Truncate | QIODevice::Text))
    {
        QMessageBox::warning(this, kernelText("kernel.device_driver.export.title", QStringLiteral("导出 TSV")), kernelText("kernel.device_driver.export.write_failed", QStringLiteral("无法写入：%1")).arg(outputPath));
        return;
    }

    outputFile.write(rowsToTsv(true).toUtf8());
    outputFile.close();
    QMessageBox::information(this, kernelText("kernel.device_driver.export.title", QStringLiteral("导出 TSV")), kernelText("kernel.device_driver.export.completed", QStringLiteral("已导出：%1")).arg(outputPath));
}

// rowsToTsv：
// - 输入 includeHeader：true 时包含中文表头；
// - 处理：把当前可见结果压平成 TSV 文本；
// - 返回：适合复制或导出的文本。
QString KernelDeviceDriverObjectsTab::rowsToTsv(const bool includeHeader) const
{
    QStringList lines;
    if (includeHeader)
    {
        lines.push_back(QStringList{
            kernelText("kernel.device_driver.header.directory", QStringLiteral("目录路径")),
            kernelText("kernel.device_driver.header.object_name", QStringLiteral("对象名称")),
            kernelText("kernel.device_driver.header.object_type", QStringLiteral("对象类型")),
            kernelText("kernel.device_driver.header.full_path", QStringLiteral("完整路径")),
            kernelText("kernel.device_driver.header.target_path", QStringLiteral("目标路径")),
            kernelText("kernel.device_driver.header.status", QStringLiteral("状态")),
            kernelText("kernel.device_driver.header.capability", QStringLiteral("能力提示")),
        }.join(QStringLiteral("\t")));
    }

    for (const KernelDeviceDriverObjectEntry& entry : m_visibleRows)
    {
        lines.push_back(QStringList{
            sanitizeTsvField(entry.directoryPathText),
            sanitizeTsvField(entry.objectNameText),
            sanitizeTsvField(entry.objectTypeText),
            sanitizeTsvField(entry.fullPathText),
            sanitizeTsvField(entry.targetPathText.isEmpty()
                ? kernelText("kernel.device_driver.placeholder.no_target", QStringLiteral("<无>"))
                : entry.targetPathText),
            sanitizeTsvField(entry.statusText),
            sanitizeTsvField(entry.capabilityHintText),
        }.join(QStringLiteral("\t")));
    }

    return lines.join(QStringLiteral("\n"));
}

// sanitizeTsvField：
// - 输入 text：原始单元格文本；
// - 处理：压平换行和制表符，避免 TSV 分列错位；
// - 返回：可安全写入 TSV 的字段文本。
QString KernelDeviceDriverObjectsTab::sanitizeTsvField(const QString& text)
{
    QString sanitizedText = text;
    sanitizedText.replace(QStringLiteral("\r"), QStringLiteral(" "));
    sanitizedText.replace(QStringLiteral("\n"), QStringLiteral(" "));
    sanitizedText.replace(QStringLiteral("\t"), QStringLiteral(" "));
    return sanitizedText;
}

// makeReadOnlyItem：
// - 输入 text：单元格文本；
// - 处理：创建只读项，统一保留原始文本并带 tooltip；
// - 返回：可直接插入表格的 QTableWidgetItem。
QTableWidgetItem* KernelDeviceDriverObjectsTab::makeReadOnlyItem(const QString& text)
{
    auto* item = new QTableWidgetItem(text);
    item->setFlags(item->flags() & ~Qt::ItemIsEditable);
    item->setToolTip(text);
    return item;
}
