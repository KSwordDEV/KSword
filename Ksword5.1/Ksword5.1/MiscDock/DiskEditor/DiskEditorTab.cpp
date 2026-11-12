#include "../../UI/KeyboardItemActivation.h"
#include "DiskEditorTab.h"
#include "../../UI/TableContextMenu.h"
#include "../../UI/AsyncOperation.h"
#include <QList>
#include "../../UI/PageControlStyle.h"
#include "../../UI/PrimaryPageStyle.h"
#include "../../UI/ParameterWorkspace.h"
#include "../../UI/FlatButtonTheme.h"
#include "../../UI/ToolbarMetrics.h"
#include "DiskEditorFormat.h"
#include "../../UI/CodeEditorWidget.h"
#include "../../../../shared/evidence/NumericTextParse.h"
#include "../../SettingsDock/AppearanceSettings.h"
#include "../../Framework/PrivilegeElevationPrompt.h"
#include "../../UI/TableInteractionSupport.h"
#include "../../UI/VisibleTableWidget.h"
#include "../../UI/FlatTableModel.h"
#include <QSortFilterProxyModel>
#include <QAbstractProxyModel>
#include "../../UI/TablePresentation.h"

// ============================================================
// DiskEditorTab.cpp
// 作用：
// 1) 实现杂项 Dock 内的磁盘编辑器页面；
// 2) 组合磁盘枚举、横向柱形图、分区表和 HEX 扇区编辑；
// 3) 通过只读默认值、显式确认和扇区对齐限制控制写盘风险。
// ============================================================

#include "DiskEditorBackend.h"
#include "DiskFileSystemForensicsPanel.h"
#include "DiskRangeTools.h"
#include "DiskMapWidget.h"
#include "DiskStructureParser.h"

#include "../../theme.h"
#include "../../UI/MemoryWorkbench/HexView.h"
#include "../../../../shared/driver/KswordArkStorageForensicsIoctl.h"

#include <QAbstractItemView>
#include <QAction>
#include <QBrush>
#include <QClipboard>
#include <QCheckBox>
#include <QComboBox>
#include <QCryptographicHash>
#include <QDateTime>
#include <QFileDialog>
#include <QGridLayout>
#include <QGroupBox>
#include <QGuiApplication>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QIcon>
#include <QInputDialog>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMessageBox>
#include <QModelIndex>
#include <QSignalBlocker>
#include <QMetaObject>
#include <QPlainTextEdit>
#include <QPointer>
#include <QPushButton>
#include <QSpinBox>
#include <QSplitter>
#include <QStringList>
#include <QTabWidget>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QVBoxLayout>

#include <algorithm>
#include <thread>

namespace {
const ks::ui::PageNavigationTabDefinition kDiskEditorTabNavigation[] = {
    {"structure", "", "", "结构解析", true},
    {"volume", "", "", "卷映射", false},
    {"health", "", "", "健康/能力", false},
    {"filesystem", "", "", "文件系统取证", false},
    {"tools", "", "", "搜索/镜像/扫描", false}
};
}

namespace
{
    // 分区表列索引：
    // - 统一列顺序；
    // - 避免后续维护时出现魔法数字。
    constexpr int kPartitionColumnNumber = 0;
    constexpr int kPartitionColumnName = 1;
    constexpr int kPartitionColumnType = 2;
    constexpr int kPartitionColumnVolume = 3;
    constexpr int kPartitionColumnOffset = 4;
    constexpr int kPartitionColumnLength = 5;
    constexpr int kPartitionColumnFlags = 6;

    // 结构字段表列索引：
    // - 保存 MBR/GPT/BootSector 解析字段；
    // - 偏移列携带 Qt::UserRole 跳转地址。
    constexpr int kStructureColumnGroup = 0;
    constexpr int kStructureColumnName = 1;
    constexpr int kStructureColumnValue = 2;
    constexpr int kStructureColumnOffset = 3;
    constexpr int kStructureColumnSize = 4;
    constexpr int kStructureColumnSeverity = 5;
    constexpr int kStructureColumnDetail = 6;

    // 搜索结果表列索引：
    // - offset 列携带绝对地址；
    // - preview 列展示命中附近 HEX。
    constexpr int kSearchColumnIndex = 0;
    constexpr int kSearchColumnOffset = 1;
    constexpr int kSearchColumnPreview = 2;

    // buildToolButtonStyle：
    // - 返回页面通用按钮样式；
    // - 与项目蓝色主题保持一致。
    QString buildToolButtonStyle()
    {
        return ks::ui::BuildFlatButtonStyle(ks::ui::FlatButtonTone::Neutral,
            ks::ui::FlatButtonAppearance::Solid);
    }

    // buildTableStyle：
    // - 返回分区表样式；
    // - 使用主题色绘制选中和表头。
    QString buildTableStyle()
    {
        return QStringLiteral(
            "QTableWidget{"
            "  border:1px solid %1;"
            "  border-radius:6px;"
            "  background:%2;"
            "  alternate-background-color:%3;"
            "  color:%4;"
            "  gridline-color:%1;"
            "}"
            "QHeaderView::section{"
            "  border:none;"
            "  border-bottom:1px solid %1;"
            "  background:transparent; /* %3 */"
            "  color:%5;"
            "  padding:5px;"
            "  font-weight:700;"
            "}")
            .arg(KswordTheme::BorderHex())
            .arg(KswordTheme::SurfaceHex())
            .arg(KswordTheme::SurfaceAltHex())
            .arg(KswordTheme::TextPrimaryHex())
            .arg(KswordTheme::PrimaryBlueHex);
    }



    // setReadOnlyItem：
    // - 创建不可编辑表格单元格；
    // - text 为展示文本；
    // - 返回 QTableWidgetItem 指针，所有权交给表格。
    QTableWidgetItem* makeReadOnlyItem(const QString& text)
    {
        QTableWidgetItem* item = new QTableWidgetItem(text);
        item->setFlags(item->flags() & ~Qt::ItemIsEditable);
        return item;
    }

    // hexOffsetText：
    // - 把偏移格式化为 16 位 HEX；
    // - value 为字节偏移；
    // - 返回 0x0000... 文本。
    using ks::misc::diskeditor_detail::HexOffsetText;

    void installDiskEditorTableCopyMenu(QTableView* table)
    {
        // installDiskEditorTableCopyMenu：
        // - 输入：磁盘编辑器中的分区/结构/搜索结果表；
        // - 处理：右键选中点击行，并把该行可见列复制为 TSV；
        // - 返回：无。菜单仅复制分析结果，不执行读写扇区动作。
        if (table == nullptr)
        {
            return;
        }

        table->setContextMenuPolicy(Qt::CustomContextMenu);
        QObject::connect(table, &QTableView::customContextMenuRequested, table, [table](const QPoint& localPosition)
        {
            const QModelIndex clickedIndex = table->indexAt(localPosition);
            if (clickedIndex.isValid())
            {
                table->setCurrentIndex(clickedIndex);
            }

            QMenu contextMenu(table);
            contextMenu.setStyleSheet(KswordTheme::ContextMenuStyle());
            QAction* copyRowAction = contextMenu.addAction(
                QIcon(QStringLiteral(":/Icon/process_copy_row.svg")),
                QStringLiteral("复制当前行"));
            // 声明业务菜单已提供此能力，避免共享表格菜单追加重复项。
            ks::ui::SetTableContextActionRole(copyRowAction, ks::ui::TableContextActionRole::CopyRows);
            copyRowAction->setEnabled(table->currentIndex().isValid());
            if (contextMenu.exec(table->viewport()->mapToGlobal(localPosition)) != copyRowAction)
            {
                return;
            }

            QClipboard* clipboardObject = QGuiApplication::clipboard();
            const int rowIndex = table->currentIndex().row();
            if (clipboardObject == nullptr || rowIndex < 0 || rowIndex >= table->model()->rowCount())
            {
                return;
            }

            QStringList rowFields;
            rowFields.reserve(table->model()->columnCount());
            for (int columnIndex = 0; columnIndex < table->model()->columnCount(); ++columnIndex)
            {
                rowFields.push_back(table->model()->index(rowIndex, columnIndex).data().toString());
            }
            clipboardObject->setText(rowFields.join(QLatin1Char('\t')));
        });
    }

    // bytesToPreviewText：
    // - 把搜索结果预览字节转成短 HEX 文本；
    // - bytes 为原始字节；
    // - 返回空格分隔的大写 HEX。
    QString bytesToPreviewText(const QByteArray& bytes)
    {
        return QString::fromLatin1(bytes.toHex(' ')).toUpper();
    }

    // createReadOnlyTable：
    // - 创建统一样式的只读表格；
    // - parent 为 Qt 父控件，headers 为表头；
    // - 返回 QTableWidget 指针，所有权交给 parent。
    QTableWidget* createReadOnlyTable(QWidget* parent, const QStringList& headers)
    {
        QTableWidget* table = new ks::ui::VisibleTableWidget(parent);
        table->setColumnCount(headers.size());
        table->setHorizontalHeaderLabels(headers);
        table->setSelectionBehavior(QAbstractItemView::SelectRows);
        table->setSelectionMode(QAbstractItemView::SingleSelection);
        table->setEditTriggers(QAbstractItemView::NoEditTriggers);
        table->setAlternatingRowColors(true);
        table->verticalHeader()->setVisible(false);
        table->horizontalHeader()->setStretchLastSection(true);
        table->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
        table->setStyleSheet(buildTableStyle());
        installDiskEditorTableCopyMenu(table);
        return table;
    }

    // applySeverityToItem：
    // - 根据严重度设置表格文本颜色；
    // - item 为待修改单元格；
    // - severity 为结构/健康项严重度；
    // - 无返回值。
    void applySeverityToItem(QTableWidgetItem* item, const ks::misc::DiskStructureSeverity severity)
    {
        if (item == nullptr)
        {
            return;
        }
        if (severity == ks::misc::DiskStructureSeverity::Error)
        {
            item->setForeground(QBrush(KswordTheme::ErrorColor()));
        }
        else if (severity == ks::misc::DiskStructureSeverity::Warning)
        {
            item->setForeground(QBrush(KswordTheme::WarningColor()));
        }
    }

    // findVolumeHintForPartition：
    // - 按区间重叠查找分区对应的卷/盘符提示；
    // - partition 为分区；
    // - volumes 为卷 extent 列表；
    // - 返回合并后的提示文本。
    QString findVolumeHintForPartition(
        const ks::misc::DiskPartitionInfo& partition,
        const std::vector<ks::misc::DiskVolumeInfo>& volumes)
    {
        QStringList hints;
        const std::uint64_t partitionEnd = partition.offsetBytes + partition.lengthBytes;
        for (const ks::misc::DiskVolumeInfo& volume : volumes)
        {
            const std::uint64_t volumeEnd = volume.offsetBytes + volume.lengthBytes;
            const bool overlap = partition.offsetBytes < volumeEnd && volume.offsetBytes < partitionEnd;
            if (!overlap)
            {
                continue;
            }
            QString hint = volume.mountPoints.isEmpty() ? volume.volumeName : volume.mountPoints;
            if (!volume.label.isEmpty())
            {
                hint += QStringLiteral(" [%1]").arg(volume.label);
            }
            if (!volume.fileSystem.isEmpty())
            {
                hint += QStringLiteral(" %1").arg(volume.fileSystem);
            }
            hints << hint;
        }
        return hints.join(QStringLiteral("; "));
    }
}

namespace ks::misc
{
    DiskEditorTab::DiskEditorTab(QWidget* parent)
        : QWidget(parent)
    {
        m_writeOperation = new ks::ui::AsyncOperation(this);
        initializeUi();
        initializeConnections();
        m_writeOperation->setStateChangedCallback([this]() {
            if (m_writeTransactionPending && !m_writeOperation->isInFlight())
            {
                finishWriteTransactionUi();
                invalidateCapturedRange();
                setControlsEnabledForBusy(false);
                appendLog(QStringLiteral("写回未通过完整验证，请重新读取磁盘。"));
            }
        });
        refreshDiskListAsync(false);
    }

    DiskEditorTab::~DiskEditorTab()
    {
        m_writeOperation->close();
    }

    void DiskEditorTab::initializeUi()
    {
        // 根布局：顶部工具栏 + 主分割区 + 底部状态。
        m_rootLayout = new QVBoxLayout(this);
        ks::ui::StyleWorkspacePage(this);

        initializeToolbar();
        initializeLayoutPanels();

        m_statusLabel = new QLabel(QStringLiteral("状态：正在枚举磁盘..."), this);
        m_statusLabel->setWordWrap(true);
        m_statusLabel->setStyleSheet(QStringLiteral("color:%1;").arg(KswordTheme::TextSecondaryHex()));
        m_rootLayout->addWidget(m_statusLabel, 0);
        // 专业 HEX 自绘保持自己的数据面，只有实际文本日志登记共享阅读主题。
        ks::ui::StyleWorkspaceTextViews(this);
    }

    void DiskEditorTab::initializeToolbar()
    {
        // 顶部工具栏聚合磁盘选择、读取范围和写入保护。
        m_toolbarWidget = new QWidget(this);
        auto* toolbarStack = new QVBoxLayout(m_toolbarWidget); // 设备、范围和保护按用途分行。
        toolbarStack->setContentsMargins(16, 12, 16, 12);
        toolbarStack->setSpacing(8);
        ks::ui::StylePrimaryToolbar(m_toolbarWidget);
        m_toolbarLayout = new QHBoxLayout();
        m_toolbarLayout->setContentsMargins(0, 0, 0, 0);
        m_toolbarLayout->setSpacing(8);
        auto* rangeLayout = new QHBoxLayout(); // 读取范围和对应动作保持同一行。
        auto* protectionLayout = new QHBoxLayout(); // 两个保护条件独立保持可读。
        toolbarStack->addLayout(m_toolbarLayout);
        toolbarStack->addLayout(rangeLayout);
        toolbarStack->addLayout(protectionLayout);
        m_rootLayout->addWidget(m_toolbarWidget, 0);

        m_diskCombo = new QComboBox(m_toolbarWidget);
        m_diskCombo->setMinimumWidth(300);
        // 设备与后端都是当前任务的输入条件，独立底面避免和导航标签混淆。
        ks::ui::StylePrimaryCombo(m_diskCombo);
        m_diskCombo->setToolTip(QStringLiteral("选择要查看的物理磁盘"));

        m_backendCombo = new QComboBox(m_toolbarWidget);
        m_backendCombo->setMinimumWidth(170);
        ks::ui::StylePrimaryCombo(m_backendCombo);
        m_backendCombo->setToolTip(QStringLiteral("选择实际磁盘访问层；端口直达绕过上层磁盘对象，控制器直达仅允许离线磁盘"));

        m_refreshButton = new QPushButton(QStringLiteral("刷新磁盘"), m_toolbarWidget);
        m_readButton = new QPushButton(QStringLiteral("读取"), m_toolbarWidget);
        m_writeButton = new QPushButton(QStringLiteral("写回"), m_toolbarWidget);
        m_partitionStartButton = new QPushButton(QStringLiteral("跳到分区起点"), m_toolbarWidget);
        m_readButton->setToolTip(QStringLiteral("读取当前偏移/长度处的磁盘数据到十六进制视图"));
        m_writeButton->setToolTip(QStringLiteral("把十六进制视图中修改过的数据写回磁盘原位置（会覆盖原数据，操作危险）"));
        m_partitionStartButton->setToolTip(QStringLiteral("把读取偏移跳转到所选分区的起始扇区"));
        m_refreshButton->setIcon(QIcon(QStringLiteral(":/Icon/process_refresh.svg")));
        m_readButton->setIcon(QIcon(QStringLiteral(":/Icon/disk_storage.svg")));
        m_writeButton->setIcon(QIcon(QStringLiteral(":/Icon/disk_save.svg")));
        m_refreshButton->setStyleSheet(buildToolButtonStyle());
        m_readButton->setStyleSheet(buildToolButtonStyle());
        m_writeButton->setStyleSheet(buildToolButtonStyle());
        m_partitionStartButton->setStyleSheet(buildToolButtonStyle());
        // 写回保留独立危险语义，保护开关和写入前确认仍由原逻辑控制。
        ks::ui::ApplyFlatButtonTheme(m_writeButton, ks::ui::FlatButtonTone::Danger,
            ks::ui::FlatButtonAppearance::Solid);

        m_offsetEdit = new QLineEdit(m_toolbarWidget);
        m_offsetEdit->setPlaceholderText(QStringLiteral("偏移，例如 0x0000000000000000"));
        m_offsetEdit->setText(QStringLiteral("0x0000000000000000"));
        m_offsetEdit->setMinimumWidth(190);
        // 磁盘读取参数属于工作台外部表单，专业 HEX 视图继续维护自身输入行为。
        ks::ui::StyleStandaloneInput(m_offsetEdit);

        m_lengthSpin = new QSpinBox(m_toolbarWidget);
        m_lengthSpin->setRange(512, 1024 * 1024);
        m_lengthSpin->setSingleStep(512);
        m_lengthSpin->setValue(4096);
        m_lengthSpin->setSuffix(QStringLiteral(" B"));
        ks::ui::StyleStandaloneInput(m_lengthSpin);

        m_readOnlyCheck = new QCheckBox(QStringLiteral("只读保护"), m_toolbarWidget);
        m_readOnlyCheck->setChecked(true);
        m_readOnlyCheck->setToolTip(QStringLiteral("开启时禁用 HEX 编辑和写回按钮"));

        m_requireAlignedCheck = new QCheckBox(QStringLiteral("R0 强制扇区对齐"), m_toolbarWidget);
        m_requireAlignedCheck->setChecked(true);
        m_requireAlignedCheck->setEnabled(false);
        m_requireAlignedCheck->setToolTip(QStringLiteral("所有访问层都由 R0 强制按逻辑扇区对齐，界面不能关闭此保护"));

        m_toolbarLayout->addWidget(new QLabel(QStringLiteral("磁盘"), m_toolbarWidget), 0);
        m_toolbarLayout->addWidget(m_diskCombo, 2);
        m_toolbarLayout->addWidget(new QLabel(QStringLiteral("访问层"), m_toolbarWidget), 0);
        m_toolbarLayout->addWidget(m_backendCombo, 0);
        m_toolbarLayout->addWidget(m_refreshButton, 0);
        rangeLayout->addWidget(new QLabel(QStringLiteral("偏移"), m_toolbarWidget), 0);
        rangeLayout->addWidget(m_offsetEdit, 1);
        rangeLayout->addWidget(new QLabel(QStringLiteral("长度"), m_toolbarWidget), 0);
        rangeLayout->addWidget(m_lengthSpin, 0);
        rangeLayout->addWidget(m_partitionStartButton, 0);
        rangeLayout->addWidget(m_readButton, 0);
        rangeLayout->addWidget(m_writeButton, 0);
        protectionLayout->addWidget(m_readOnlyCheck, 0);
        protectionLayout->addWidget(m_requireAlignedCheck, 0);
        protectionLayout->addStretch(1);
        ks::ui::NormalizeToolbarRow(m_toolbarLayout);
        ks::ui::NormalizeToolbarRow(rangeLayout);
        ks::ui::NormalizeToolbarRow(protectionLayout);
        ks::ui::StyleParameterFields(m_toolbarWidget);
    }

    void DiskEditorTab::initializeLayoutPanels()
    {
        m_mainSplitter = new QSplitter(Qt::Horizontal, this);
        m_rootLayout->addWidget(m_mainSplitter, 1);

        QWidget* leftPanel = new QWidget(m_mainSplitter);
        QVBoxLayout* leftLayout = new QVBoxLayout(leftPanel);
        leftLayout->setContentsMargins(16, 16, 16, 16);
        leftLayout->setSpacing(12);
        ks::ui::StylePrimaryContentPanel(leftPanel, false);

        m_diskMapWidget = new DiskMapWidget(leftPanel);
        leftLayout->addWidget(m_diskMapWidget, 0);

        m_partitionTable = new ks::ui::VisibleTableWidget(leftPanel);
        m_partitionTable->setColumnCount(7);
        m_partitionTable->setHorizontalHeaderLabels({
            QStringLiteral("#"),
            QStringLiteral("名称"),
            QStringLiteral("类型"),
            QStringLiteral("卷/盘符"),
            QStringLiteral("起始偏移"),
            QStringLiteral("容量"),
            QStringLiteral("标记")
            });
        m_partitionTable->setSelectionBehavior(QAbstractItemView::SelectRows);
        m_partitionTable->setSelectionMode(QAbstractItemView::SingleSelection);
        m_partitionTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
        m_partitionTable->setAlternatingRowColors(true);
        m_partitionTable->verticalHeader()->setVisible(false);
        m_partitionTable->horizontalHeader()->setStretchLastSection(true);
        m_partitionTable->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
        m_partitionTable->setStyleSheet(buildTableStyle());
        installDiskEditorTableCopyMenu(m_partitionTable);
        // 分区表是 HEX 跳转选择器，已有复制菜单，隐藏无关快照。
        ks::ui::SetTableActionBarMode(m_partitionTable, ks::ui::TableActionBarMode::None);
        leftLayout->addWidget(m_partitionTable, 0);

        m_hexEditor = new ks::ui::HexView(leftPanel);
        m_hexEditor->setEditable(false);
        m_hexEditor->setBytesPerRow(16);
        leftLayout->addWidget(m_hexEditor, 1);

        m_advancedTabs = new QTabWidget(leftPanel);
        ks::ui::StylePageTabsContentFrame(m_advancedTabs);
        initializeAdvancedPanels(m_advancedTabs);
        leftLayout->addWidget(m_advancedTabs, 1);

        QWidget* rightPanel = new QWidget(m_mainSplitter);
        QVBoxLayout* rightLayout = new QVBoxLayout(rightPanel);
        rightLayout->setContentsMargins(16, 16, 16, 16);
        rightLayout->setSpacing(12);
        ks::ui::StylePrimaryContentPanel(rightPanel, false);

        QGroupBox* diskSummaryGroup = new QGroupBox(QStringLiteral("磁盘摘要"), rightPanel);
        ks::ui::StylePrimaryGroup(diskSummaryGroup);
        QVBoxLayout* diskSummaryLayout = new QVBoxLayout(diskSummaryGroup);
        m_diskSummaryLabel = new QLabel(QStringLiteral("等待磁盘枚举..."), diskSummaryGroup);
        m_diskSummaryLabel->setWordWrap(true);
        m_diskSummaryLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
        diskSummaryLayout->addWidget(m_diskSummaryLabel);
        ks::ui::StyleParameterSection(diskSummaryGroup);
        rightLayout->addWidget(diskSummaryGroup, 0);

        QGroupBox* partitionDetailGroup = new QGroupBox(QStringLiteral("分区详情"), rightPanel);
        ks::ui::StylePrimaryGroup(partitionDetailGroup);
        QVBoxLayout* partitionDetailLayout = new QVBoxLayout(partitionDetailGroup);
        m_partitionDetailLabel = new QLabel(QStringLiteral("尚未选择分区。"), partitionDetailGroup);
        m_partitionDetailLabel->setWordWrap(true);
        m_partitionDetailLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
        partitionDetailLayout->addWidget(m_partitionDetailLabel);
        ks::ui::StyleParameterSection(partitionDetailGroup);
        rightLayout->addWidget(partitionDetailGroup, 0);

        QGroupBox* logGroup = new QGroupBox(QStringLiteral("操作日志"), rightPanel);
        ks::ui::StylePrimaryGroup(logGroup);
        QVBoxLayout* logLayout = new QVBoxLayout(logGroup);
        m_logEdit = new CodeEditorWidget(logGroup);
        m_logEdit->setReadOnly(true);
        // 日志主题、工具和原文追加由共享外壳处理。
        logLayout->addWidget(m_logEdit, 1);
        ks::ui::StyleParameterSection(logGroup);
        rightLayout->addWidget(logGroup, 1);

        m_mainSplitter->addWidget(leftPanel);
        m_mainSplitter->addWidget(rightPanel);
        m_mainSplitter->setStretchFactor(0, 4);
        m_mainSplitter->setStretchFactor(1, 1);
        m_mainSplitter->setSizes({ 980, 300 });
    }

    void DiskEditorTab::initializeAdvancedPanels(QWidget* parent)
    {
        // 高级页保持只读分析与工具操作分离，减少误写盘入口。
        QWidget* structurePage = new QWidget(parent);
        QVBoxLayout* structureLayout = new QVBoxLayout(structurePage);
        structureLayout->setContentsMargins(4, 4, 4, 4);
        structureLayout->setSpacing(6);

        QHBoxLayout* structureToolbar = new QHBoxLayout();
        m_analyzeButton = new QPushButton(QStringLiteral("刷新结构解析"), structurePage);
        m_analyzeButton->setIcon(QIcon(QStringLiteral(":/Icon/disk_analyze.svg")));
        m_analyzeButton->setStyleSheet(buildToolButtonStyle());
        structureToolbar->addWidget(m_analyzeButton, 0);
        structureToolbar->addWidget(new QLabel(QStringLiteral("解析 MBR/GPT/启动扇区，校验 CRC，并映射卷/盘符。"), structurePage), 1);
        ks::ui::NormalizeToolbarRow(structureToolbar);
        structureLayout->addLayout(structureToolbar);

        m_structureTable = createReadOnlyTable(structurePage, {
            QStringLiteral("分组"),
            QStringLiteral("字段"),
            QStringLiteral("值"),
            QStringLiteral("偏移"),
            QStringLiteral("长度"),
            QStringLiteral("等级"),
            QStringLiteral("说明")
            });
        // 解析出的字段映射是静态磁盘结构，不需要冻结对比栏。
        ks::ui::SetTableActionBarMode(m_structureTable, ks::ui::TableActionBarMode::None);
        structureLayout->addWidget(m_structureTable, 1);
        m_navigationTabs.add(kDiskEditorTabNavigation[0], m_advancedTabs, structurePage, QIcon(QStringLiteral(":/Icon/disk_analyze.svg")));

        QWidget* volumePage = new QWidget(parent);
        QVBoxLayout* volumeLayout = new QVBoxLayout(volumePage);
        volumeLayout->setContentsMargins(4, 4, 4, 4);
        m_volumeTable = createReadOnlyTable(volumePage, {
            QStringLiteral("卷"),
            QStringLiteral("盘符/挂载点"),
            QStringLiteral("设备路径"),
            QStringLiteral("文件系统"),
            QStringLiteral("卷标"),
            QStringLiteral("起始偏移"),
            QStringLiteral("长度")
            });
        // 所选磁盘的卷映射小表是定位信息，隐藏重复工具条。
        ks::ui::SetTableActionBarMode(m_volumeTable, ks::ui::TableActionBarMode::None);
        volumeLayout->addWidget(m_volumeTable, 1);
        m_navigationTabs.add(kDiskEditorTabNavigation[1], m_advancedTabs, volumePage, QIcon(QStringLiteral(":/Icon/disk_volume.svg")));

        QWidget* healthPage = new QWidget(parent);
        QVBoxLayout* healthLayout = new QVBoxLayout(healthPage);
        healthLayout->setContentsMargins(4, 4, 4, 4);
        m_healthTable = createReadOnlyTable(healthPage, {
            QStringLiteral("类别"),
            QStringLiteral("项目"),
            QStringLiteral("值"),
            QStringLiteral("等级"),
            QStringLiteral("说明")
            });
        // 健康与能力键值摘要不需要快照对比栏。
        ks::ui::SetTableActionBarMode(m_healthTable, ks::ui::TableActionBarMode::None);
        healthLayout->addWidget(m_healthTable, 1);
        m_navigationTabs.add(kDiskEditorTabNavigation[2], m_advancedTabs, healthPage, QIcon(QStringLiteral(":/Icon/disk_health.svg")));

        auto* fileSystemForensicsPanel = new DiskFileSystemForensicsPanel(
            [this]() -> std::optional<DiskForensicsSelection>
            {
                const DiskDeviceInfo* disk = currentDisk();
                const DiskPartitionInfo* partition = currentPartition();
                if (disk == nullptr
                    || partition == nullptr
                    || partition->lengthBytes == 0U
                    || partition->kind == DiskPartitionKind::Unallocated)
                {
                    return std::nullopt;
                }
                DiskForensicsSelection selection;
                selection.diskIndex = disk->diskIndex;
                selection.backend = currentRawBackend();
                selection.partitionOffset = partition->offsetBytes;
                selection.partitionLength = partition->lengthBytes;
                selection.logicalSectorSize = disk->bytesPerSector;
                selection.backendMask = disk->rawBackendMask;
                selection.capabilityFlags = disk->rawCapabilityFlags;
                selection.displayText = QStringLiteral("%1 / %2")
                    .arg(disk->devicePath)
                    .arg(partition->name);
                return selection;
            },
            [this](const std::uint64_t absoluteOffset)
            {
                m_offsetEdit->setText(HexOffsetText(absoluteOffset));
                readCurrentRangeAsync(QStringLiteral("文件系统取证跳转读取"));
            },
            parent);
        m_navigationTabs.add(kDiskEditorTabNavigation[3], m_advancedTabs, fileSystemForensicsPanel, QIcon(QStringLiteral(":/Icon/disk_volume.svg")));

        QWidget* toolPage = new QWidget(parent);
        QVBoxLayout* toolLayout = new QVBoxLayout(toolPage);
        // 内层参数工作区已有 16px 留白，不再额外叠加工具页边距。
        toolLayout->setContentsMargins(0, 0, 0, 0);
        // 工具页先选范围、再执行，分区间距大于区内行距。
        toolLayout->setSpacing(16);

        // 范围操作是参数工具，磁盘目录/十六进制主工作区仍保留原来的浏览布局。
        auto* workspace = new ks::ui::ParameterWorkspace(toolPage, 460);
        workspace->useWideParameterLayout(60);
        toolLayout->addWidget(workspace, 1);

        QGroupBox* rangeGroup = new QGroupBox(QStringLiteral("范围与文件"), toolPage);
        ks::ui::StylePrimaryGroup(rangeGroup);
        QGridLayout* rangeLayout = new QGridLayout(rangeGroup);
        m_toolOffsetEdit = new QLineEdit(rangeGroup);
        m_toolOffsetEdit->setText(QStringLiteral("0x0000000000000000"));
        ks::ui::StyleStandaloneInput(m_toolOffsetEdit);
        m_toolLengthEdit = new QLineEdit(rangeGroup);
        m_toolLengthEdit->setText(QStringLiteral("0x100000"));
        ks::ui::StyleStandaloneInput(m_toolLengthEdit);
        m_toolFileEdit = new QLineEdit(rangeGroup);
        m_toolFileEdit->setPlaceholderText(QStringLiteral("镜像导出/导入/对比文件路径"));
        ks::ui::StyleStandaloneInput(m_toolFileEdit);
        m_toolUseSelectionButton = new QPushButton(QStringLiteral("填入当前范围"), rangeGroup);
        m_toolUsePartitionButton = new QPushButton(QStringLiteral("填入所选分区"), rangeGroup);
        m_toolUseSelectionButton->setToolTip(QStringLiteral("用当前读取/选中的范围填入下方工具的偏移和长度"));
        m_toolUsePartitionButton->setToolTip(QStringLiteral("用当前所选分区的范围填入下方工具的偏移和长度"));
        m_toolBrowseOpenButton = new QPushButton(QStringLiteral("选择输入文件…"), rangeGroup);
        m_toolBrowseSaveButton = new QPushButton(QStringLiteral("选择保存位置…"), rangeGroup);
        for (QPushButton* button : { m_toolUseSelectionButton, m_toolUsePartitionButton, m_toolBrowseOpenButton, m_toolBrowseSaveButton })
        {
            button->setStyleSheet(buildToolButtonStyle());
        }
        rangeLayout->addWidget(new QLabel(QStringLiteral("偏移"), rangeGroup), 0, 0);
        rangeLayout->addWidget(m_toolOffsetEdit, 0, 1);
        rangeLayout->addWidget(new QLabel(QStringLiteral("长度"), rangeGroup), 1, 0);
        rangeLayout->addWidget(m_toolLengthEdit, 1, 1);
        rangeLayout->addWidget(m_toolUseSelectionButton, 2, 0);
        rangeLayout->addWidget(m_toolUsePartitionButton, 2, 1);
        rangeLayout->addWidget(new QLabel(QStringLiteral("文件"), rangeGroup), 3, 0);
        rangeLayout->addWidget(m_toolFileEdit, 3, 1);
        rangeLayout->addWidget(m_toolBrowseOpenButton, 4, 0);
        rangeLayout->addWidget(m_toolBrowseSaveButton, 4, 1);
        rangeLayout->setColumnStretch(1, 1);
        // 范围表单保留栅格和路径输入语义，统一其单行控件尺寸。
        rangeLayout->setHorizontalSpacing(8);
        rangeLayout->setVerticalSpacing(8);
        for (QWidget* control : QList<QWidget*>{ m_toolOffsetEdit, m_toolLengthEdit, m_toolFileEdit,
            m_toolUseSelectionButton, m_toolUsePartitionButton, m_toolBrowseOpenButton, m_toolBrowseSaveButton })
        {
            ks::ui::NormalizeToolbarControl(control);
        }
        ks::ui::StyleParameterSection(rangeGroup);
        workspace->parameters()->addWidget(rangeGroup);

        QGroupBox* actionGroup = new QGroupBox(QStringLiteral("范围操作"), toolPage);
        ks::ui::StylePrimaryGroup(actionGroup);
        QGridLayout* actionLayout = new QGridLayout(actionGroup);
        m_searchPatternEdit = new QLineEdit(actionGroup);
        m_searchPatternEdit->setPlaceholderText(QStringLiteral("搜索：AA BB ?? 或 ASCII/UTF-16 文本"));
        ks::ui::StyleStandaloneInput(m_searchPatternEdit);
        m_searchModeCombo = new QComboBox(actionGroup);
        m_searchModeCombo->addItem(QStringLiteral("HEX 字节/??通配"), static_cast<int>(DiskSearchPatternMode::HexBytes));
        m_searchModeCombo->addItem(QStringLiteral("ASCII 文本"), static_cast<int>(DiskSearchPatternMode::AsciiText));
        m_searchModeCombo->addItem(QStringLiteral("UTF-16 文本"), static_cast<int>(DiskSearchPatternMode::Utf16Text));
        ks::ui::StylePrimaryCombo(m_searchModeCombo);
        m_hashAlgorithmCombo = new QComboBox(actionGroup);
        m_hashAlgorithmCombo->addItem(QStringLiteral("SHA-256"), static_cast<int>(QCryptographicHash::Sha256));
        m_hashAlgorithmCombo->addItem(QStringLiteral("SHA-1"), static_cast<int>(QCryptographicHash::Sha1));
        m_hashAlgorithmCombo->addItem(QStringLiteral("MD5"), static_cast<int>(QCryptographicHash::Md5));
        ks::ui::StylePrimaryCombo(m_hashAlgorithmCombo);
        m_maxResultSpin = new QSpinBox(actionGroup);
        m_maxResultSpin->setRange(1, 10000);
        m_maxResultSpin->setValue(512);
        ks::ui::StyleStandaloneInput(m_maxResultSpin);
        m_scanBlockSpin = new QSpinBox(actionGroup);
        m_scanBlockSpin->setRange(512, 8 * 1024 * 1024);
        m_scanBlockSpin->setSingleStep(4096);
        m_scanBlockSpin->setValue(1024 * 1024);
        m_scanBlockSpin->setSuffix(QStringLiteral(" B"));
        ks::ui::StyleStandaloneInput(m_scanBlockSpin);
        m_searchButton = new QPushButton(QStringLiteral("搜索"), actionGroup);
        m_hashButton = new QPushButton(QStringLiteral("计算哈希"), actionGroup);
        m_exportButton = new QPushButton(QStringLiteral("导出镜像"), actionGroup);
        m_importButton = new QPushButton(QStringLiteral("导入写盘"), actionGroup);
        m_compareButton = new QPushButton(QStringLiteral("对比文件"), actionGroup);
        m_scanButton = new QPushButton(QStringLiteral("坏道扫描"), actionGroup);
        m_hashButton->setToolTip(QStringLiteral("计算所选磁盘区间的哈希值，用于校验数据一致性"));
        m_importButton->setToolTip(QStringLiteral("把外部文件的内容写入磁盘指定位置（会覆盖原有数据，操作危险）"));
        m_scanButton->setToolTip(QStringLiteral("按块顺序读取所选磁盘范围，检测可读性与坏道"));
        m_maxResultSpin->setToolTip(QStringLiteral("搜索结果最多保留的条数，超出后停止记录"));
        m_scanBlockSpin->setToolTip(QStringLiteral("每次读取的块大小；块越大速度越快，定位坏道的位置越粗"));
        for (QPushButton* button : { m_searchButton, m_hashButton, m_exportButton, m_importButton, m_compareButton, m_scanButton })
        {
            button->setStyleSheet(buildToolButtonStyle());
        }
        m_importButton->setIcon(QIcon(QStringLiteral(":/Icon/disk_warning.svg")));
        ks::ui::ApplyFlatButtonTheme(m_importButton, ks::ui::FlatButtonTone::Danger,
            ks::ui::FlatButtonAppearance::Solid);
        actionLayout->addWidget(new QLabel(QStringLiteral("搜索"), actionGroup), 0, 0);
        actionLayout->addWidget(m_searchPatternEdit, 0, 1);
        actionLayout->addWidget(m_searchModeCombo, 1, 0);
        actionLayout->addWidget(m_searchButton, 1, 1);
        actionLayout->addWidget(new QLabel(QStringLiteral("哈希"), actionGroup), 2, 0);
        actionLayout->addWidget(m_hashAlgorithmCombo, 2, 1);
        actionLayout->addWidget(m_hashButton, 3, 0, 1, 2);
        actionLayout->addWidget(m_exportButton, 4, 0);
        actionLayout->addWidget(m_compareButton, 4, 1);
        actionLayout->addWidget(m_importButton, 5, 0, 1, 2);
        actionLayout->addWidget(new QLabel(QStringLiteral("结果上限/块大小"), actionGroup), 6, 0, 1, 2);
        actionLayout->addWidget(m_maxResultSpin, 7, 0);
        actionLayout->addWidget(m_scanBlockSpin, 7, 1);
        actionLayout->addWidget(m_scanButton, 8, 0, 1, 2);
        actionLayout->setColumnStretch(1, 1);
        // 扫描模式/字节模式仍是业务输入，不改成表格过滤框。
        actionLayout->setHorizontalSpacing(8);
        actionLayout->setVerticalSpacing(8);
        for (QWidget* control : QList<QWidget*>{ m_searchPatternEdit, m_searchModeCombo, m_hashAlgorithmCombo,
            m_maxResultSpin, m_scanBlockSpin, m_searchButton, m_hashButton, m_exportButton, m_importButton,
            m_compareButton, m_scanButton })
        {
            ks::ui::NormalizeToolbarControl(control);
        }
        ks::ui::StyleParameterSection(actionGroup);
        workspace->parameters()->addWidget(actionGroup);

        m_searchResultTable = new ks::ui::TableActionTableView(toolPage);
        using SearchModel = ks::ui::FlatTableModel<DiskSearchDisplayRow>;
        m_searchResultModel = new SearchModel({
            {QStringLiteral("#")}, {QStringLiteral("命中偏移")}, {QStringLiteral("预览 HEX")}},
            [](const DiskSearchDisplayRow& row, const int column, const int role) -> QVariant
            {
                if (column == kSearchColumnOffset && role == Qt::UserRole)
                    return QVariant::fromValue<qulonglong>(row.hit.offsetBytes);
                if (role != Qt::DisplayRole) return {};
                switch (column)
                {
                case kSearchColumnIndex: return QString::number(row.ordinal);
                case kSearchColumnOffset: return HexOffsetText(row.hit.offsetBytes);
                case kSearchColumnPreview: return bytesToPreviewText(row.hit.preview);
                default: return {};
                }
            }, m_searchResultTable);
        auto* searchProxy = new QSortFilterProxyModel(m_searchResultTable);
        searchProxy->setSourceModel(m_searchResultModel);
        m_searchResultTable->setModel(searchProxy);
        m_searchResultTable->setSelectionBehavior(QAbstractItemView::SelectRows);
        m_searchResultTable->setSelectionMode(QAbstractItemView::SingleSelection);
        m_searchResultTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
        m_searchResultTable->setAlternatingRowColors(true);
        m_searchResultTable->verticalHeader()->setVisible(false);
        m_searchResultTable->horizontalHeader()->setStretchLastSection(true);
        m_searchResultTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
        m_searchResultTable->setSortingEnabled(true);
        m_searchResultTable->sortByColumn(-1, Qt::AscendingOrder);
        ks::ui::ApplyTablePresentation(m_searchResultTable);
        installDiskEditorTableCopyMenu(m_searchResultTable);
        // 字节搜索命中结果保留复制导出，收拢无关现场快照。
        ks::ui::SetTableActionBarMode(m_searchResultTable, ks::ui::TableActionBarMode::Compact);
        workspace->results()->addWidget(m_searchResultTable, 1);
        ks::ui::ArrangeParameterColumns(workspace->parameters(),
            { rangeGroup }, { actionGroup }, 300);
        workspace->finish();
        m_navigationTabs.add(kDiskEditorTabNavigation[4], m_advancedTabs, toolPage, QIcon(QStringLiteral(":/Icon/disk_tools.svg")));

    }

    void DiskEditorTab::initializeConnections()
    {
        connect(m_refreshButton, &QPushButton::clicked, this, [this]()
        {
            refreshDiskListAsync(true);
        });

        connect(m_diskCombo, &QComboBox::currentIndexChanged, this, [this](const int index)
        {
            Q_UNUSED(index);
            invalidateCapturedRange();
            m_structureReport = DiskStructureReport{};
            updateDiskSummary();
            rebuildRawBackendSelector();
            rebuildPartitionTable();
            rebuildStructureTable();
            rebuildVolumeTable();
            rebuildHealthTable();
            const DiskDeviceInfo* disk = currentDisk();
            if (disk != nullptr)
            {
                m_diskMapWidget->setDisk(*disk);
                if (!disk->partitions.empty())
                {
                    m_diskMapWidget->setSelectedPartitionIndex(disk->partitions.front().tableIndex);
                }
                appendLog(QStringLiteral("切换到 %1。").arg(disk->devicePath));
                refreshStructureReportAsync(QStringLiteral("切换磁盘自动解析"));
            }
            else
            {
                m_diskMapWidget->clearDisk();
            }
        });

        connect(m_diskMapWidget, &DiskMapWidget::partitionActivated, this, [this](const int partitionIndex)
        {
            syncPartitionSelection(partitionIndex, true);
        });

        connect(m_partitionTable, &QTableWidget::currentCellChanged, this,
            [this](const int currentRow, const int currentColumn, const int previousRow, const int previousColumn)
        {
            Q_UNUSED(currentColumn);
            Q_UNUSED(previousRow);
            Q_UNUSED(previousColumn);
            if (currentRow < 0)
            {
                return;
            }
            QTableWidgetItem* item = m_partitionTable->item(currentRow, kPartitionColumnNumber);
            if (item == nullptr)
            {
                return;
            }
            syncPartitionSelection(item->data(Qt::UserRole).toInt(), false);
        });

        connect(m_partitionStartButton, &QPushButton::clicked, this, [this]()
        {
            const DiskPartitionInfo* partition = currentPartition();
            if (partition == nullptr)
            {
                appendLog(QStringLiteral("未选择分区，无法跳转到分区起点。"));
                return;
            }
            m_offsetEdit->setText(HexOffsetText(partition->offsetBytes));
            readCurrentRangeAsync(QStringLiteral("读取当前分区起点"));
        });

        connect(m_readButton, &QPushButton::clicked, this, [this]()
        {
            readCurrentRangeAsync(QStringLiteral("手动读取"));
        });

        connect(m_backendCombo, &QComboBox::currentIndexChanged, this, [this](const int index)
        {
            Q_UNUSED(index);
            invalidateCapturedRange();
            appendLog(QStringLiteral("磁盘访问层切换为：%1。")
                .arg(m_backendCombo->currentText()));
        });

        connect(m_writeButton, &QPushButton::clicked, this, [this]()
        {
            writeCurrentBuffer();
        });

        connect(m_readOnlyCheck, &QCheckBox::toggled, this, [this](const bool checked)
        {
            if (m_hexEditor != nullptr)
            {
                m_hexEditor->setEditable(!checked);
            }
            if (m_writeButton != nullptr)
            {
                m_writeButton->setEnabled(!checked && !m_busy && hasWritableCapture());
            }
            if (m_importButton != nullptr)
            {
                m_importButton->setEnabled(!checked && !m_busy);
            }
            appendLog(checked
                ? QStringLiteral("只读保护已开启，HEX 编辑和写回被禁用。")
                : QStringLiteral("只读保护已关闭，允许编辑当前缓冲；写盘仍需要二次确认。"));
        });

        connect(m_hexEditor, &ks::ui::HexView::byteEdited, this,
            [this](const std::uint64_t absoluteAddress, const std::uint8_t oldValue, const std::uint8_t newValue)
        {
            updateDirtyState(true);
            appendLog(QStringLiteral("编辑字节 %1: %2 -> %3")
                .arg(HexOffsetText(absoluteAddress))
                .arg(oldValue, 2, 16, QChar('0'))
                .arg(newValue, 2, 16, QChar('0'))
                .toUpper());
        });

        connect(m_analyzeButton, &QPushButton::clicked, this, [this]()
        {
            refreshStructureReportAsync(QStringLiteral("手动刷新结构解析"));
        });

        ks::ui::InstallKeyboardItemActivation(m_structureTable);
        connect(m_structureTable, &QTableWidget::cellDoubleClicked, this,
            [this](const int row, const int column)
        {
            Q_UNUSED(column);
            QTableWidgetItem* item = m_structureTable->item(row, kStructureColumnOffset);
            if (item == nullptr)
            {
                return;
            }
            const std::uint64_t offset = item->data(Qt::UserRole).toULongLong();
            m_offsetEdit->setText(HexOffsetText(offset));
            readCurrentRangeAsync(QStringLiteral("结构字段跳转读取"));
        });

        ks::ui::InstallKeyboardItemActivation(m_volumeTable);
        connect(m_volumeTable, &QTableWidget::cellDoubleClicked, this,
            [this](const int row, const int column)
        {
            Q_UNUSED(column);
            QTableWidgetItem* item = m_volumeTable->item(row, 5);
            if (item == nullptr)
            {
                return;
            }
            const std::uint64_t offset = item->data(Qt::UserRole).toULongLong();
            m_offsetEdit->setText(HexOffsetText(offset));
            readCurrentRangeAsync(QStringLiteral("卷映射跳转读取"));
        });

        ks::ui::InstallKeyboardItemActivation(m_searchResultTable);
        connect(m_searchResultTable, &QTableView::doubleClicked, this,
            [this](const QModelIndex& index)
            {
                QModelIndex source = index;
                while (source.isValid() && source.model() != m_searchResultModel)
                {
                    const auto* proxy = qobject_cast<const QAbstractProxyModel*>(source.model());
                    if (proxy == nullptr) return;
                    source = proxy->mapToSource(source);
                }
                const DiskSearchDisplayRow* hit = source.isValid()
                    && source.model() == m_searchResultModel ? m_searchResultModel->rowAt(source.row()) : nullptr;
                if (hit == nullptr) return;
                m_offsetEdit->setText(HexOffsetText(hit->hit.offsetBytes));
                readCurrentRangeAsync(QStringLiteral("搜索结果跳转读取"));
            });

        connect(m_toolUseSelectionButton, &QPushButton::clicked, this, [this]()
        {
            updateToolRangeFromSelection(false);
        });

        connect(m_toolUsePartitionButton, &QPushButton::clicked, this, [this]()
        {
            updateToolRangeFromSelection(true);
        });

        connect(m_toolBrowseOpenButton, &QPushButton::clicked, this, [this]()
        {
            browseToolFile(false);
        });

        connect(m_toolBrowseSaveButton, &QPushButton::clicked, this, [this]()
        {
            browseToolFile(true);
        });

        connect(m_searchButton, &QPushButton::clicked, this, [this]()
        {
            runSearchAsync();
        });

        connect(m_hashButton, &QPushButton::clicked, this, [this]()
        {
            runHashAsync();
        });

        connect(m_exportButton, &QPushButton::clicked, this, [this]()
        {
            runExportAsync();
        });

        connect(m_importButton, &QPushButton::clicked, this, [this]()
        {
            runImportAsync();
        });

        connect(m_compareButton, &QPushButton::clicked, this, [this]()
        {
            runCompareAsync();
        });

        connect(m_scanButton, &QPushButton::clicked, this, [this]()
        {
            runScanAsync();
        });
    }

    void DiskEditorTab::refreshDiskListAsync(const bool forceRefresh)
    {
        if (m_busy)
        {
            appendLog(QStringLiteral("当前已有后台任务，刷新请求被忽略。"));
            return;
        }

        m_busy = true;
        setControlsEnabledForBusy(true);
        if (m_statusLabel != nullptr)
        {
            m_statusLabel->setText(forceRefresh ? QStringLiteral("状态：正在刷新磁盘列表...") : QStringLiteral("状态：正在枚举磁盘..."));
        }

        QPointer<DiskEditorTab> safeThis(this);
        std::thread([safeThis]()
        {
            std::vector<DiskDeviceInfo> disks;
            QString errorText;
            DiskEditorBackend::enumerateDisks(disks, errorText);

            if (safeThis.isNull())
            {
                return;
            }

            const bool invokeOk = QMetaObject::invokeMethod(
                safeThis.data(),
                [safeThis, disks = std::move(disks), errorText]() mutable
                {
                    if (safeThis.isNull())
                    {
                        return;
                    }
                    safeThis->applyDiskList(std::move(disks), errorText);
                },
                Qt::QueuedConnection);
            if (!invokeOk && !safeThis.isNull())
            {
                QMetaObject::invokeMethod(
                    safeThis.data(),
                    [safeThis]()
                    {
                        if (!safeThis.isNull())
                        {
                            safeThis->m_busy = false;
                            safeThis->setControlsEnabledForBusy(false);
                        }
                    },
                    Qt::QueuedConnection);
            }
        }).detach();
    }

    void DiskEditorTab::applyDiskList(std::vector<DiskDeviceInfo> disks, const QString& errorText)
    {
        const QList<QTableView*> diskEditorTables = {
            m_partitionTable,
            m_structureTable,
            m_volumeTable,
            m_healthTable
        };
        if (ks::ui::IsTableUiCommitBlockedByContextMenu(diskEditorTables))
        {
            const QPointer<DiskEditorTab> safeThis(this);
            ks::ui::DeferTableUiCommitIfContextMenuOpen(
                this,
                QStringLiteral("disk-editor-device-list-apply"),
                diskEditorTables,
                [safeThis, disks = std::move(disks), errorText]() mutable
                {
                    if (!safeThis.isNull())
                    {
                        safeThis->applyDiskList(
                            std::move(disks),
                            errorText);
                    }
                });
            return;
        }

        invalidateCapturedRange();
        m_disks = std::move(disks);
        m_diskCombo->blockSignals(true);
        m_diskCombo->clear();
        for (int index = 0; index < static_cast<int>(m_disks.size()); ++index)
        {
            const DiskDeviceInfo& disk = m_disks[static_cast<std::size_t>(index)];
            m_diskCombo->addItem(disk.displayName.isEmpty() ? disk.devicePath : disk.displayName, index);
        }
        m_diskCombo->blockSignals(false);

        if (!m_disks.empty())
        {
            m_diskCombo->setCurrentIndex(0);
            updateDiskSummary();
            rebuildRawBackendSelector();
            rebuildPartitionTable();
            m_diskMapWidget->setDisk(m_disks.front());
            if (!m_disks.front().partitions.empty())
            {
                m_diskMapWidget->setSelectedPartitionIndex(m_disks.front().partitions.front().tableIndex);
            }
            m_statusLabel->setText(QStringLiteral("状态：已枚举 %1 个磁盘。").arg(static_cast<int>(m_disks.size())));
            appendLog(QStringLiteral("磁盘枚举完成，共 %1 个条目。").arg(static_cast<int>(m_disks.size())));
        }
        else
        {
            m_diskMapWidget->clearDisk();
            m_partitionTable->setRowCount(0);
            m_hexEditor->clearBuffer();
            m_structureReport = DiskStructureReport{};
            rebuildStructureTable();
            rebuildVolumeTable();
            rebuildHealthTable();
            (void)ks::ui::promptForPrivilegeFailure(this, QStringLiteral("枚举物理磁盘"), errorText);
            m_statusLabel->setText(QStringLiteral("状态：磁盘枚举失败：%1").arg(errorText));
            appendLog(QStringLiteral("磁盘枚举失败：%1").arg(errorText));
        }

        m_busy = false;
        setControlsEnabledForBusy(false);

        if (!m_disks.empty())
        {
            refreshStructureReportAsync(QStringLiteral("枚举完成自动解析"));
        }
    }

    const DiskDeviceInfo* DiskEditorTab::currentDisk() const
    {
        if (m_diskCombo == nullptr)
        {
            return nullptr;
        }
        if (!m_diskCombo->currentData().isValid())
        {
            return nullptr;
        }
        const int diskVectorIndex = m_diskCombo->currentData().toInt();
        if (diskVectorIndex < 0 || diskVectorIndex >= static_cast<int>(m_disks.size()))
        {
            return nullptr;
        }
        return &m_disks[static_cast<std::size_t>(diskVectorIndex)];
    }

    const DiskPartitionInfo* DiskEditorTab::currentPartition() const
    {
        const DiskDeviceInfo* disk = currentDisk();
        if (disk == nullptr || m_selectedPartitionIndex < 0)
        {
            return nullptr;
        }

        for (const DiskPartitionInfo& partition : disk->partitions)
        {
            if (partition.tableIndex == m_selectedPartitionIndex)
            {
                return &partition;
            }
        }
        return nullptr;
    }

    void DiskEditorTab::rebuildRawBackendSelector()
    {
        if (m_backendCombo == nullptr)
        {
            return;
        }

        const QSignalBlocker blocker(m_backendCombo);
        m_backendCombo->clear();
        const DiskDeviceInfo* disk = currentDisk();
        const std::uint32_t backendMask = disk == nullptr ? 1U : disk->rawBackendMask;
        if ((backendMask & 0x1U) != 0U)
        {
            m_backendCombo->addItem(
                QStringLiteral("Windows 存储栈"),
                static_cast<int>(KSWORD_ARK_RAW_DISK_BACKEND_WINDOWS_STACK));
        }
        if ((backendMask & 0x2U) != 0U)
        {
            m_backendCombo->addItem(
                QStringLiteral("存储端口直达"),
                static_cast<int>(KSWORD_ARK_RAW_DISK_BACKEND_STORAGE_PORT));
        }
        if ((backendMask & 0x4U) != 0U)
        {
            m_backendCombo->addItem(
                QStringLiteral("离线控制器直达"),
                static_cast<int>(KSWORD_ARK_RAW_DISK_BACKEND_CONTROLLER));
        }
        if (m_backendCombo->count() == 0)
        {
            m_backendCombo->addItem(
                QStringLiteral("Windows 存储栈"),
                static_cast<int>(KSWORD_ARK_RAW_DISK_BACKEND_WINDOWS_STACK));
        }
        m_backendCombo->setCurrentIndex(0);
        if (disk != nullptr)
        {
            m_backendCombo->setToolTip(disk->rawBackendDetail);
        }
    }

    unsigned long DiskEditorTab::currentRawBackend() const
    {
        if (m_backendCombo == nullptr
            || !m_backendCombo->currentData().isValid())
        {
            return KSWORD_ARK_RAW_DISK_BACKEND_WINDOWS_STACK;
        }
        return static_cast<unsigned long>(
            m_backendCombo->currentData().toULongLong());
    }

    void DiskEditorTab::updateDiskSummary()
    {
        const DiskDeviceInfo* disk = currentDisk();
        if (disk == nullptr)
        {
            m_diskSummaryLabel->setText(QStringLiteral("未选择磁盘。"));
            return;
        }

        m_diskSummaryLabel->setText(
            QStringLiteral(
                "设备：%1\n"
                "型号：%2\n"
                "厂商：%3\n"
                "序列号：%4\n"
                "总线：%5\n"
                "介质：%6\n"
                "容量：%7 (%8 字节)\n"
                "分区表：%9\n"
                "逻辑扇区：%10 B\n"
                "物理扇区：%11 B\n"
                "打开状态：%12\n"
                "访问层预检：%13")
            .arg(disk->devicePath)
            .arg(disk->model.isEmpty() ? QStringLiteral("<未知>") : disk->model)
            .arg(disk->vendor.isEmpty() ? QStringLiteral("<未知>") : disk->vendor)
            .arg(disk->serial.isEmpty() ? QStringLiteral("<未知>") : disk->serial)
            .arg(disk->busType.isEmpty() ? QStringLiteral("<未知>") : disk->busType)
            .arg(disk->mediaType.isEmpty() ? QStringLiteral("<未知>") : disk->mediaType)
            .arg(DiskEditorBackend::formatBytes(disk->sizeBytes))
            .arg(static_cast<qulonglong>(disk->sizeBytes))
            .arg(DiskEditorBackend::partitionStyleText(disk->partitionStyle))
            .arg(disk->bytesPerSector)
            .arg(disk->physicalBytesPerSector == 0 ? disk->bytesPerSector : disk->physicalBytesPerSector)
            .arg(disk->openErrorText.isEmpty() ? QStringLiteral("可读") : disk->openErrorText)
            .arg(disk->rawBackendDetail.isEmpty()
                ? QStringLiteral("未返回 R0 预检")
                : disk->rawBackendDetail));
    }

    void DiskEditorTab::rebuildPartitionTable()
    {
        const DiskDeviceInfo* disk = currentDisk();
        m_partitionTable->setRowCount(0);
        m_selectedPartitionIndex = -1;
        m_partitionDetailLabel->setText(QStringLiteral("尚未选择分区。"));

        if (disk == nullptr)
        {
            return;
        }

        m_partitionTable->setRowCount(static_cast<int>(disk->partitions.size()));
        for (int row = 0; row < static_cast<int>(disk->partitions.size()); ++row)
        {
            const DiskPartitionInfo& partition = disk->partitions[static_cast<std::size_t>(row)];

            QTableWidgetItem* numberItem = makeReadOnlyItem(partition.partitionNumber == 0
                ? QStringLiteral("-")
                : QString::number(partition.partitionNumber));
            numberItem->setData(Qt::UserRole, partition.tableIndex);
            m_partitionTable->setItem(row, kPartitionColumnNumber, numberItem);
            m_partitionTable->setItem(row, kPartitionColumnName, makeReadOnlyItem(partition.name));
            m_partitionTable->setItem(row, kPartitionColumnType, makeReadOnlyItem(partition.typeText));
            m_partitionTable->setItem(row, kPartitionColumnVolume, makeReadOnlyItem(partition.volumeHint));
            m_partitionTable->setItem(row, kPartitionColumnOffset, makeReadOnlyItem(HexOffsetText(partition.offsetBytes)));
            m_partitionTable->setItem(row, kPartitionColumnLength, makeReadOnlyItem(DiskEditorBackend::formatBytes(partition.lengthBytes)));
            m_partitionTable->setItem(row, kPartitionColumnFlags, makeReadOnlyItem(partition.flagsText));
        }

        m_partitionTable->resizeColumnsToContents();
        if (!disk->partitions.empty())
        {
            syncPartitionSelection(disk->partitions.front().tableIndex, false);
        }
    }

    void DiskEditorTab::rebuildVolumeHints()
    {
        // m_disks 中的分区缓存用于 UI 展示，卷映射只回填当前磁盘。
        const int diskVectorIndex = (m_diskCombo == nullptr || !m_diskCombo->currentData().isValid())
            ? -1
            : m_diskCombo->currentData().toInt();
        if (diskVectorIndex < 0 || diskVectorIndex >= static_cast<int>(m_disks.size()))
        {
            return;
        }

        DiskDeviceInfo& disk = m_disks[static_cast<std::size_t>(diskVectorIndex)];
        const int previousSelection = m_selectedPartitionIndex;
        for (DiskPartitionInfo& partition : disk.partitions)
        {
            partition.volumeHint = findVolumeHintForPartition(partition, m_structureReport.volumes);
        }

        rebuildPartitionTable();
        if (previousSelection >= 0)
        {
            syncPartitionSelection(previousSelection, false);
        }
    }

    void DiskEditorTab::syncPartitionSelection(const int partitionIndex, const bool focusHex)
    {
        const DiskDeviceInfo* disk = currentDisk();
        if (disk == nullptr)
        {
            return;
        }

        const DiskPartitionInfo* selected = nullptr;
        for (const DiskPartitionInfo& partition : disk->partitions)
        {
            if (partition.tableIndex == partitionIndex)
            {
                selected = &partition;
                break;
            }
        }
        if (selected == nullptr)
        {
            return;
        }

        m_selectedPartitionIndex = partitionIndex;
        m_diskMapWidget->setSelectedPartitionIndex(partitionIndex);

        for (int row = 0; row < m_partitionTable->rowCount(); ++row)
        {
            QTableWidgetItem* item = m_partitionTable->item(row, kPartitionColumnNumber);
            if (item != nullptr && item->data(Qt::UserRole).toInt() == partitionIndex)
            {
                if (m_partitionTable->currentRow() != row)
                {
                    QSignalBlocker tableSignalBlocker(m_partitionTable);
                    m_partitionTable->setCurrentCell(row, 0);
                }
                break;
            }
        }

        m_offsetEdit->setText(HexOffsetText(selected->offsetBytes));
        m_partitionDetailLabel->setText(
            QStringLiteral(
                "名称：%1\n"
                "类型：%2\n"
                "分区号：%3\n"
                "起始偏移：%4 (%5)\n"
                "长度：%6 (%7 字节)\n"
                "结束偏移：%8\n"
                "样式：%9\n"
                "唯一标识：%10\n"
                "卷提示：%11\n"
                "标记：%12")
            .arg(selected->name.isEmpty() ? QStringLiteral("<未命名>") : selected->name)
            .arg(selected->typeText.isEmpty() ? QStringLiteral("<未知>") : selected->typeText)
            .arg(selected->partitionNumber == 0 ? QStringLiteral("-") : QString::number(selected->partitionNumber))
            .arg(HexOffsetText(selected->offsetBytes))
            .arg(static_cast<qulonglong>(selected->offsetBytes))
            .arg(DiskEditorBackend::formatBytes(selected->lengthBytes))
            .arg(static_cast<qulonglong>(selected->lengthBytes))
            .arg(HexOffsetText(selected->offsetBytes + selected->lengthBytes))
            .arg(DiskEditorBackend::partitionStyleText(selected->style))
            .arg(selected->uniqueIdText.isEmpty() ? QStringLiteral("-") : selected->uniqueIdText)
            .arg(selected->volumeHint.isEmpty() ? QStringLiteral("-") : selected->volumeHint)
            .arg(selected->flagsText.isEmpty() ? QStringLiteral("-") : selected->flagsText));

        if (focusHex)
        {
            readCurrentRangeAsync(QStringLiteral("点击分区读取起点"));
        }
    }

    void DiskEditorTab::refreshStructureReportAsync(const QString& reasonText)
    {
        const DiskDeviceInfo* disk = currentDisk();
        if (disk == nullptr)
        {
            appendLog(QStringLiteral("结构解析失败：未选择磁盘。"));
            return;
        }
        if (m_busy)
        {
            appendLog(QStringLiteral("结构解析请求被忽略：当前已有后台任务。"));
            return;
        }

        const DiskDeviceInfo diskSnapshot = *disk;
        const unsigned long backend = currentRawBackend();
        const std::uint64_t diskLimit = diskSnapshot.sizeBytes == 0
            ? 16ULL * 1024ULL * 1024ULL
            : diskSnapshot.sizeBytes;
        const std::uint64_t bytesToRead64 = std::min<std::uint64_t>(
            std::max<std::uint64_t>(1024ULL * 1024ULL, static_cast<std::uint64_t>(diskSnapshot.bytesPerSector) * 4096ULL),
            diskLimit);
        const std::uint32_t bytesToRead = static_cast<std::uint32_t>(std::min<std::uint64_t>(
            bytesToRead64,
            16ULL * 1024ULL * 1024ULL));

        m_busy = true;
        setControlsEnabledForBusy(true);
        m_statusLabel->setText(QStringLiteral("状态：正在解析磁盘结构..."));
        appendLog(QStringLiteral("%1：读取前部 %2 用于结构解析。")
            .arg(reasonText)
            .arg(DiskEditorBackend::formatBytes(bytesToRead)));

        QPointer<DiskEditorTab> safeThis(this);
        std::thread([safeThis, diskSnapshot, backend, bytesToRead]()
        {
            QByteArray leadingBytes;
            QString readError;
            DiskEditorBackend::readBytesWithBackend(
                diskSnapshot.diskIndex,
                backend,
                0,
                bytesToRead,
                leadingBytes,
                readError);

            DiskStructureReport report;
            QString parseError;
            if (readError.isEmpty())
            {
                report = DiskStructureParser::buildReport(diskSnapshot, leadingBytes, parseError);
            }
            else
            {
                parseError = readError;
            }

            if (safeThis.isNull())
            {
                return;
            }

            QMetaObject::invokeMethod(
                safeThis.data(),
                [safeThis, report = std::move(report), parseError]() mutable
                {
                    if (safeThis.isNull())
                    {
                        return;
                    }
                    safeThis->applyStructureReport(std::move(report), parseError);
                },
                Qt::QueuedConnection);
        }).detach();
    }

    void DiskEditorTab::applyStructureReport(DiskStructureReport report, const QString& errorText)
    {
        const QList<QTableView*> structureTables = {
            m_structureTable,
            m_volumeTable,
            m_healthTable
        };
        if (ks::ui::IsTableUiCommitBlockedByContextMenu(structureTables))
        {
            const QPointer<DiskEditorTab> safeThis(this);
            ks::ui::DeferTableUiCommitIfContextMenuOpen(
                this,
                QStringLiteral("disk-editor-structure-report-apply"),
                structureTables,
                [safeThis, report = std::move(report), errorText]() mutable
                {
                    if (!safeThis.isNull())
                    {
                        safeThis->applyStructureReport(
                            std::move(report),
                            errorText);
                    }
                });
            return;
        }

        if (!errorText.isEmpty())
        {
            (void)ks::ui::promptForPrivilegeFailure(this, QStringLiteral("解析物理磁盘结构"), errorText);
            appendLog(QStringLiteral("结构解析失败：%1").arg(errorText));
            m_statusLabel->setText(QStringLiteral("状态：结构解析失败：%1").arg(errorText));
        }
        else
        {
            m_structureReport = std::move(report);
            rebuildStructureTable();
            rebuildVolumeTable();
            rebuildHealthTable();
            rebuildVolumeHints();
            for (const QString& warning : m_structureReport.warnings)
            {
                appendLog(QStringLiteral("结构解析提示：%1").arg(warning));
            }
            appendLog(QStringLiteral("结构解析完成：字段 %1，卷映射 %2，健康项 %3。")
                .arg(static_cast<int>(m_structureReport.fields.size()))
                .arg(static_cast<int>(m_structureReport.volumes.size()))
                .arg(static_cast<int>(m_structureReport.healthItems.size())));
            m_statusLabel->setText(QStringLiteral("状态：结构解析完成。"));
        }

        m_busy = false;
        setControlsEnabledForBusy(false);
    }

    void DiskEditorTab::rebuildStructureTable()
    {
        if (m_structureTable == nullptr)
        {
            return;
        }
        m_structureTable->setRowCount(static_cast<int>(m_structureReport.fields.size()));
        for (int row = 0; row < static_cast<int>(m_structureReport.fields.size()); ++row)
        {
            const DiskStructureField& field = m_structureReport.fields[static_cast<std::size_t>(row)];
            QTableWidgetItem* offsetItem = makeReadOnlyItem(HexOffsetText(field.offsetBytes));
            offsetItem->setData(Qt::UserRole, static_cast<qulonglong>(field.offsetBytes));
            m_structureTable->setItem(row, kStructureColumnGroup, makeReadOnlyItem(field.group));
            m_structureTable->setItem(row, kStructureColumnName, makeReadOnlyItem(field.name));
            m_structureTable->setItem(row, kStructureColumnValue, makeReadOnlyItem(field.value));
            m_structureTable->setItem(row, kStructureColumnOffset, offsetItem);
            m_structureTable->setItem(row, kStructureColumnSize, makeReadOnlyItem(QString::number(field.sizeBytes)));
            m_structureTable->setItem(row, kStructureColumnSeverity, makeReadOnlyItem(severityText(field.severity)));
            m_structureTable->setItem(row, kStructureColumnDetail, makeReadOnlyItem(field.detail));
            for (int column = 0; column < m_structureTable->columnCount(); ++column)
            {
                applySeverityToItem(m_structureTable->item(row, column), field.severity);
            }
        }
        m_structureTable->resizeColumnsToContents();
    }

    void DiskEditorTab::rebuildVolumeTable()
    {
        if (m_volumeTable == nullptr)
        {
            return;
        }
        m_volumeTable->setRowCount(static_cast<int>(m_structureReport.volumes.size()));
        for (int row = 0; row < static_cast<int>(m_structureReport.volumes.size()); ++row)
        {
            const DiskVolumeInfo& volume = m_structureReport.volumes[static_cast<std::size_t>(row)];
            QTableWidgetItem* offsetItem = makeReadOnlyItem(HexOffsetText(volume.offsetBytes));
            offsetItem->setData(Qt::UserRole, static_cast<qulonglong>(volume.offsetBytes));
            m_volumeTable->setItem(row, 0, makeReadOnlyItem(volume.volumeName));
            m_volumeTable->setItem(row, 1, makeReadOnlyItem(volume.mountPoints));
            m_volumeTable->setItem(row, 2, makeReadOnlyItem(volume.devicePath));
            m_volumeTable->setItem(row, 3, makeReadOnlyItem(volume.fileSystem));
            m_volumeTable->setItem(row, 4, makeReadOnlyItem(volume.label));
            m_volumeTable->setItem(row, 5, offsetItem);
            m_volumeTable->setItem(row, 6, makeReadOnlyItem(DiskEditorBackend::formatBytes(volume.lengthBytes)));
        }
        m_volumeTable->resizeColumnsToContents();
    }

    void DiskEditorTab::rebuildHealthTable()
    {
        if (m_healthTable == nullptr)
        {
            return;
        }
        m_healthTable->setRowCount(static_cast<int>(m_structureReport.healthItems.size()));
        for (int row = 0; row < static_cast<int>(m_structureReport.healthItems.size()); ++row)
        {
            const DiskHealthItem& item = m_structureReport.healthItems[static_cast<std::size_t>(row)];
            m_healthTable->setItem(row, 0, makeReadOnlyItem(item.category));
            m_healthTable->setItem(row, 1, makeReadOnlyItem(item.name));
            m_healthTable->setItem(row, 2, makeReadOnlyItem(item.value));
            m_healthTable->setItem(row, 3, makeReadOnlyItem(severityText(item.severity)));
            m_healthTable->setItem(row, 4, makeReadOnlyItem(item.detail));
            for (int column = 0; column < m_healthTable->columnCount(); ++column)
            {
                applySeverityToItem(m_healthTable->item(row, column), item.severity);
            }
        }
        m_healthTable->resizeColumnsToContents();
    }

    void DiskEditorTab::runSearchAsync()
    {
        const DiskDeviceInfo* disk = currentDisk();
        if (disk == nullptr)
        {
            appendLog(QStringLiteral("搜索失败：未选择磁盘。"));
            return;
        }
        if (m_busy)
        {
            appendLog(QStringLiteral("搜索请求被忽略：当前已有后台任务。"));
            return;
        }

        std::uint64_t offset = 0;
        std::uint64_t length = 0;
        if (!parseToolRange(offset, length))
        {
            return;
        }
        if (m_searchPatternEdit->text().trimmed().isEmpty())
        {
            QMessageBox::warning(this, QStringLiteral("磁盘搜索"), QStringLiteral("搜索模式为空。"));
            return;
        }

        const QString devicePath = disk->devicePath;
        const QString patternText = m_searchPatternEdit->text();
        const auto mode = static_cast<DiskSearchPatternMode>(m_searchModeCombo->currentData().toInt());
        const int maxResults = m_maxResultSpin->value();
        m_busy = true;
        setControlsEnabledForBusy(true);
        m_searchResultModel->clearRows();
        m_statusLabel->setText(QStringLiteral("状态：正在搜索磁盘范围..."));
        appendLog(QStringLiteral("开始搜索：offset=%1 length=%2 pattern=%3")
            .arg(HexOffsetText(offset))
            .arg(DiskEditorBackend::formatBytes(length))
            .arg(patternText));

        QPointer<DiskEditorTab> safeThis(this);
        std::thread([safeThis, devicePath, offset, length, patternText, mode, maxResults]()
        {
            DiskRangeTaskResult result = DiskRangeTools::searchRange(
                devicePath,
                offset,
                length,
                patternText,
                mode,
                maxResults);
            if (safeThis.isNull())
            {
                return;
            }
            QMetaObject::invokeMethod(
                safeThis.data(),
                [safeThis, result = std::move(result)]() mutable
                {
                    if (!safeThis.isNull())
                    {
                        safeThis->applyRangeTaskResult(QStringLiteral("搜索"), std::move(result));
                    }
                },
                Qt::QueuedConnection);
        }).detach();
    }

    void DiskEditorTab::runHashAsync()
    {
        const DiskDeviceInfo* disk = currentDisk();
        if (disk == nullptr)
        {
            appendLog(QStringLiteral("哈希失败：未选择磁盘。"));
            return;
        }
        if (m_busy)
        {
            appendLog(QStringLiteral("哈希请求被忽略：当前已有后台任务。"));
            return;
        }

        std::uint64_t offset = 0;
        std::uint64_t length = 0;
        if (!parseToolRange(offset, length))
        {
            return;
        }

        const QString devicePath = disk->devicePath;
        const auto algorithm = static_cast<QCryptographicHash::Algorithm>(m_hashAlgorithmCombo->currentData().toInt());
        m_busy = true;
        setControlsEnabledForBusy(true);
        m_statusLabel->setText(QStringLiteral("状态：正在计算范围哈希..."));
        appendLog(QStringLiteral("开始哈希：offset=%1 length=%2 algorithm=%3")
            .arg(HexOffsetText(offset))
            .arg(DiskEditorBackend::formatBytes(length))
            .arg(m_hashAlgorithmCombo->currentText()));

        QPointer<DiskEditorTab> safeThis(this);
        std::thread([safeThis, devicePath, offset, length, algorithm]()
        {
            DiskRangeTaskResult result = DiskRangeTools::hashRange(devicePath, offset, length, algorithm);
            if (safeThis.isNull())
            {
                return;
            }
            QMetaObject::invokeMethod(
                safeThis.data(),
                [safeThis, result = std::move(result)]() mutable
                {
                    if (!safeThis.isNull())
                    {
                        safeThis->applyRangeTaskResult(QStringLiteral("哈希"), std::move(result));
                    }
                },
                Qt::QueuedConnection);
        }).detach();
    }

    void DiskEditorTab::runExportAsync()
    {
        const DiskDeviceInfo* disk = currentDisk();
        if (disk == nullptr)
        {
            appendLog(QStringLiteral("导出失败：未选择磁盘。"));
            return;
        }
        if (m_busy)
        {
            appendLog(QStringLiteral("导出请求被忽略：当前已有后台任务。"));
            return;
        }

        std::uint64_t offset = 0;
        std::uint64_t length = 0;
        if (!parseToolRange(offset, length))
        {
            return;
        }
        const QString filePath = m_toolFileEdit->text().trimmed();
        if (filePath.isEmpty())
        {
            QMessageBox::warning(this, QStringLiteral("镜像导出"), QStringLiteral("请先选择导出文件路径。"));
            return;
        }

        const QString devicePath = disk->devicePath;
        m_busy = true;
        setControlsEnabledForBusy(true);
        m_statusLabel->setText(QStringLiteral("状态：正在导出镜像片段..."));
        appendLog(QStringLiteral("开始导出：offset=%1 length=%2 file=%3")
            .arg(HexOffsetText(offset))
            .arg(DiskEditorBackend::formatBytes(length))
            .arg(filePath));

        QPointer<DiskEditorTab> safeThis(this);
        std::thread([safeThis, devicePath, offset, length, filePath]()
        {
            DiskRangeTaskResult result = DiskRangeTools::exportRangeToFile(devicePath, offset, length, filePath);
            if (safeThis.isNull())
            {
                return;
            }
            QMetaObject::invokeMethod(
                safeThis.data(),
                [safeThis, result = std::move(result)]() mutable
                {
                    if (!safeThis.isNull())
                    {
                        safeThis->applyRangeTaskResult(QStringLiteral("导出"), std::move(result));
                    }
                },
                Qt::QueuedConnection);
        }).detach();
    }

    void DiskEditorTab::runImportAsync()
    {
        const DiskDeviceInfo* disk = currentDisk();
        if (disk == nullptr)
        {
            appendLog(QStringLiteral("导入失败：未选择磁盘。"));
            return;
        }
        if (m_busy)
        {
            appendLog(QStringLiteral("导入请求被忽略：当前已有后台任务。"));
            return;
        }
        if (m_readOnlyCheck->isChecked())
        {
            QMessageBox::information(this, QStringLiteral("镜像导入"), QStringLiteral("只读保护已开启，请先关闭只读保护。"));
            return;
        }

        std::uint64_t offset = 0;
        std::uint64_t ignoredLength = 0;
        if (!parseToolRange(offset, ignoredLength))
        {
            return;
        }
        const QString filePath = m_toolFileEdit->text().trimmed();
        if (filePath.isEmpty())
        {
            QMessageBox::warning(this, QStringLiteral("镜像导入"), QStringLiteral("请先选择导入文件。"));
            return;
        }

        if (!ks::settings::dangerousActionConfirmationsSuppressed())
        {
            // 确认改为直接点击：不再要求输入确认短语，默认聚焦“否”避免误触。
            const auto importDecision = QMessageBox::warning(
                this,
                QStringLiteral("确认导入写盘"),
                QStringLiteral("该操作会把文件直接写入 %1 @ %2，覆盖原有数据且不可撤销。\n文件：%3\n\n确认写入？")
                    .arg(disk->devicePath)
                    .arg(HexOffsetText(offset))
                    .arg(filePath),
                QMessageBox::Yes | QMessageBox::No,
                QMessageBox::No);
            if (importDecision != QMessageBox::Yes)
            {
                appendLog(QStringLiteral("导入已取消：用户在确认中选择了否。"));
                return;
            }
        }
        else
        {
            appendLog(QStringLiteral(
                "高风险提示：重复危险确认已关闭；镜像导入仍可能破坏分区表、文件系统或启动数据。"));
        }

        const QString devicePath = disk->devicePath;
        const std::uint32_t bytesPerSector = disk->bytesPerSector;
        const bool requireAligned = m_requireAlignedCheck->isChecked();
        m_busy = true;
        setControlsEnabledForBusy(true);
        m_statusLabel->setText(QStringLiteral("状态：正在导入文件到磁盘..."));
        appendLog(QStringLiteral("开始导入：offset=%1 file=%2").arg(HexOffsetText(offset), filePath));

        QPointer<DiskEditorTab> safeThis(this);
        std::thread([safeThis, devicePath, offset, filePath, bytesPerSector, requireAligned]()
        {
            DiskRangeTaskResult result = DiskRangeTools::importFileToRange(
                devicePath,
                offset,
                filePath,
                bytesPerSector,
                requireAligned);
            if (safeThis.isNull())
            {
                return;
            }
            QMetaObject::invokeMethod(
                safeThis.data(),
                [safeThis, result = std::move(result)]() mutable
                {
                    if (!safeThis.isNull())
                    {
                        safeThis->applyRangeTaskResult(QStringLiteral("导入"), std::move(result));
                    }
                },
                Qt::QueuedConnection);
        }).detach();
    }

    void DiskEditorTab::runCompareAsync()
    {
        const DiskDeviceInfo* disk = currentDisk();
        if (disk == nullptr)
        {
            appendLog(QStringLiteral("对比失败：未选择磁盘。"));
            return;
        }
        if (m_busy)
        {
            appendLog(QStringLiteral("对比请求被忽略：当前已有后台任务。"));
            return;
        }

        std::uint64_t offset = 0;
        std::uint64_t length = 0;
        if (!parseToolRange(offset, length))
        {
            return;
        }
        const QString filePath = m_toolFileEdit->text().trimmed();
        if (filePath.isEmpty())
        {
            QMessageBox::warning(this, QStringLiteral("文件对比"), QStringLiteral("请先选择对比文件。"));
            return;
        }

        const QString devicePath = disk->devicePath;
        const int maxDifferences = m_maxResultSpin->value();
        m_busy = true;
        setControlsEnabledForBusy(true);
        m_statusLabel->setText(QStringLiteral("状态：正在对比磁盘范围和文件..."));
        appendLog(QStringLiteral("开始对比：offset=%1 length=%2 file=%3")
            .arg(HexOffsetText(offset))
            .arg(DiskEditorBackend::formatBytes(length))
            .arg(filePath));

        QPointer<DiskEditorTab> safeThis(this);
        std::thread([safeThis, devicePath, offset, length, filePath, maxDifferences]()
        {
            DiskRangeTaskResult result = DiskRangeTools::compareRangeWithFile(
                devicePath,
                offset,
                length,
                filePath,
                maxDifferences);
            if (safeThis.isNull())
            {
                return;
            }
            QMetaObject::invokeMethod(
                safeThis.data(),
                [safeThis, result = std::move(result)]() mutable
                {
                    if (!safeThis.isNull())
                    {
                        safeThis->applyRangeTaskResult(QStringLiteral("对比"), std::move(result));
                    }
                },
                Qt::QueuedConnection);
        }).detach();
    }

    void DiskEditorTab::runScanAsync()
    {
        const DiskDeviceInfo* disk = currentDisk();
        if (disk == nullptr)
        {
            appendLog(QStringLiteral("坏道扫描失败：未选择磁盘。"));
            return;
        }
        if (m_busy)
        {
            appendLog(QStringLiteral("坏道扫描请求被忽略：当前已有后台任务。"));
            return;
        }

        std::uint64_t offset = 0;
        std::uint64_t length = 0;
        if (!parseToolRange(offset, length))
        {
            return;
        }

        const QString devicePath = disk->devicePath;
        const std::uint32_t blockBytes = static_cast<std::uint32_t>(m_scanBlockSpin->value());
        m_busy = true;
        setControlsEnabledForBusy(true);
        m_statusLabel->setText(QStringLiteral("状态：正在坏道扫描..."));
        appendLog(QStringLiteral("开始坏道扫描：offset=%1 length=%2 block=%3")
            .arg(HexOffsetText(offset))
            .arg(DiskEditorBackend::formatBytes(length))
            .arg(blockBytes));

        QPointer<DiskEditorTab> safeThis(this);
        std::thread([safeThis, devicePath, offset, length, blockBytes]()
        {
            DiskRangeTaskResult result = DiskRangeTools::scanReadableBlocks(
                devicePath,
                offset,
                length,
                blockBytes);
            if (safeThis.isNull())
            {
                return;
            }
            QMetaObject::invokeMethod(
                safeThis.data(),
                [safeThis, result = std::move(result)]() mutable
                {
                    if (!safeThis.isNull())
                    {
                        safeThis->applyRangeTaskResult(QStringLiteral("坏道扫描"), std::move(result));
                    }
                },
                Qt::QueuedConnection);
        }).detach();
    }

    void DiskEditorTab::applyRangeTaskResult(const QString& taskName, DiskRangeTaskResult result)
    {
        if (taskName == QStringLiteral("搜索") &&
            ks::ui::IsTableUiCommitBlockedByContextMenu({m_searchResultTable}))
        {
            const QPointer<DiskEditorTab> safeThis(this);
            ks::ui::DeferTableUiCommitIfContextMenuOpen(
                this,
                QStringLiteral("disk-editor-search-result-apply"),
                {m_searchResultTable},
                [safeThis, taskName, result = std::move(result)]() mutable
                {
                    if (!safeThis.isNull())
                    {
                        safeThis->applyRangeTaskResult(
                            taskName,
                            std::move(result));
                    }
                });
            return;
        }

        if (!result.errorText.isEmpty())
        {
            // privilegePromptHandled：避免提权提示后紧接着显示相互冲突的旧失败框。
            const bool privilegePromptHandled =
                ks::ui::promptForPrivilegeFailure(this, taskName, result.errorText);
            appendLog(QStringLiteral("%1失败：%2").arg(taskName, result.errorText));
            m_statusLabel->setText(QStringLiteral("状态：%1失败：%2").arg(taskName, result.errorText));
            if (!privilegePromptHandled)
            {
                QMessageBox::warning(
                    this,
                    QStringLiteral("磁盘工具"),
                    QStringLiteral("%1失败：%2").arg(taskName, result.errorText));
            }
        }
        else
        {
            appendLog(QStringLiteral("%1：%2").arg(taskName, result.summary));
            for (const QString& line : result.detailLines)
            {
                appendLog(QStringLiteral("%1明细：%2").arg(taskName, line));
            }
            m_statusLabel->setText(QStringLiteral("状态：%1").arg(result.summary));
        }

        if (taskName == QStringLiteral("搜索") && m_searchResultTable != nullptr)
        {
            std::vector<DiskSearchDisplayRow> rows;
            rows.reserve(result.searchResults.size());
            for (std::size_t index = 0; index < result.searchResults.size(); ++index)
            {
                rows.push_back({index + 1, std::move(result.searchResults[index])});
            }
            m_searchResultModel->setRows(std::move(rows));
        }

        if (taskName == QStringLiteral("导入") && result.success)
        {
            m_busy = false;
            setControlsEnabledForBusy(false);
            refreshStructureReportAsync(QStringLiteral("导入后刷新结构解析"));
            return;
        }

        m_busy = false;
        setControlsEnabledForBusy(false);
    }

    void DiskEditorTab::updateDirtyState(const bool dirty)
    {
        m_dirty = dirty;
        if (m_writeButton != nullptr)
        {
            m_writeButton->setEnabled(!m_readOnlyCheck->isChecked() && !m_busy && hasWritableCapture());
            m_writeButton->setText(m_dirty ? QStringLiteral("写回*") : QStringLiteral("写回"));
            m_writeButton->setIcon(QIcon(m_dirty
                ? QStringLiteral(":/Icon/disk_warning.svg")
                : QStringLiteral(":/Icon/disk_save.svg")));
        }
    }

    void DiskEditorTab::appendLog(const QString& message)
    {
        if (m_logEdit == nullptr)
        {
            return;
        }
        const QString line = QStringLiteral("[%1] %2")
            .arg(QDateTime::currentDateTime().toString(QStringLiteral("HH:mm:ss")))
            .arg(message);
        m_logEdit->appendRawText(line);
    }

    QString DiskEditorTab::severityText(const DiskStructureSeverity severity)
    {
        switch (severity)
        {
        case DiskStructureSeverity::Error: return QStringLiteral("错误");
        case DiskStructureSeverity::Warning: return QStringLiteral("警告");
        case DiskStructureSeverity::Info: break;
        }
        return QStringLiteral("信息");
    }

    void DiskEditorTab::updateToolRangeFromSelection(const bool usePartitionRange)
    {
        if (usePartitionRange)
        {
            const DiskPartitionInfo* partition = currentPartition();
            if (partition == nullptr)
            {
                appendLog(QStringLiteral("无法同步工具范围：未选择分区。"));
                return;
            }
            m_toolOffsetEdit->setText(HexOffsetText(partition->offsetBytes));
            m_toolLengthEdit->setText(HexOffsetText(partition->lengthBytes));
            appendLog(QStringLiteral("工具范围已设置为当前分区：%1 + %2。")
                .arg(HexOffsetText(partition->offsetBytes))
                .arg(DiskEditorBackend::formatBytes(partition->lengthBytes)));
            return;
        }

        std::uint64_t offset = 0;
        if (!parseAddressText(m_offsetEdit->text(), offset))
        {
            offset = m_loadedBaseOffset;
        }
        m_toolOffsetEdit->setText(HexOffsetText(offset));
        m_toolLengthEdit->setText(HexOffsetText(static_cast<std::uint64_t>(m_lengthSpin->value())));
        appendLog(QStringLiteral("工具范围已设置为当前读取范围。"));
    }

    void DiskEditorTab::browseToolFile(const bool saveMode)
    {
        const QString filePath = saveMode
            ? QFileDialog::getSaveFileName(this, QStringLiteral("选择镜像保存路径"), QString(), QStringLiteral("镜像文件 (*.bin *.img *.dd);;所有文件 (*.*)"))
            : QFileDialog::getOpenFileName(this, QStringLiteral("选择输入文件"), QString(), QStringLiteral("镜像/二进制文件 (*.bin *.img *.dd);;所有文件 (*.*)"));
        if (!filePath.isEmpty())
        {
            m_toolFileEdit->setText(filePath);
        }
    }

    bool DiskEditorTab::parseToolRange(std::uint64_t& offsetOut, std::uint64_t& lengthOut) const
    {
        if (!parseAddressText(m_toolOffsetEdit->text(), offsetOut))
        {
            QMessageBox::warning(const_cast<DiskEditorTab*>(this), QStringLiteral("磁盘工具"), QStringLiteral("工具偏移格式无效。"));
            return false;
        }
        if (!parseAddressText(m_toolLengthEdit->text(), lengthOut))
        {
            QMessageBox::warning(const_cast<DiskEditorTab*>(this), QStringLiteral("磁盘工具"), QStringLiteral("工具长度格式无效。"));
            return false;
        }
        if (lengthOut == 0)
        {
            QMessageBox::warning(const_cast<DiskEditorTab*>(this), QStringLiteral("磁盘工具"), QStringLiteral("工具长度不能为 0。"));
            return false;
        }

        const DiskDeviceInfo* disk = currentDisk();
        if (disk != nullptr && disk->sizeBytes != 0)
        {
            if (offsetOut >= disk->sizeBytes)
            {
                QMessageBox::warning(const_cast<DiskEditorTab*>(this), QStringLiteral("磁盘工具"), QStringLiteral("工具偏移超出磁盘容量。"));
                return false;
            }
            const std::uint64_t maxLength = disk->sizeBytes - offsetOut;
            if (lengthOut > maxLength)
            {
                lengthOut = maxLength;
            }
        }
        return true;
    }

    bool DiskEditorTab::parseAddressText(const QString& text, std::uint64_t& valueOut)
    {
        // 本页三个输入框（偏移、范围起点、范围长度）的默认值与所有回填都由
        // hexOffsetText 产生，形如 0x0000000000000000，界面上从头到尾只有
        // 十六进制。所以无前缀时必须也按十六进制解释：照着框里原有的样子清空
        // 重打一个 100000，按十进制读会变成 0x186A0，落到磁盘上另一个位置——
        // 而这一页是**会写盘的**，读错位置只是看错数据，写错位置会毁数据。
        // 原先这里与 MemoryDock 是同一份"先十进制、失败再十六进制"的写法，
        // 那条回退只对含 a–f 的串生效，纯数字串永远走不到。
        valueOut = 0ULL;
        const auto parsed = ksword::evidence::ParseNumericText(
            text.trimmed().toStdString(),
            ksword::evidence::NumericTextDefaultRadix::Hexadecimal);
        if (!parsed.ok)
        {
            return false;
        }
        valueOut = parsed.value;
        return true;
    }

    void DiskEditorTab::setControlsEnabledForBusy(const bool busy)
    {
        if (m_refreshButton != nullptr)
        {
            m_refreshButton->setEnabled(!busy);
        }
        if (m_readButton != nullptr)
        {
            m_readButton->setEnabled(!busy);
        }
        if (m_partitionStartButton != nullptr)
        {
            m_partitionStartButton->setEnabled(!busy);
        }
        if (m_diskCombo != nullptr)
        {
            m_diskCombo->setEnabled(!busy);
        }
        if (m_backendCombo != nullptr)
        {
            m_backendCombo->setEnabled(!busy);
        }
        if (m_writeButton != nullptr)
        {
            m_writeButton->setEnabled(!busy && !m_readOnlyCheck->isChecked() && hasWritableCapture());
        }
        for (QPushButton* button : {
            m_analyzeButton,
            m_toolUseSelectionButton,
            m_toolUsePartitionButton,
            m_toolBrowseOpenButton,
            m_toolBrowseSaveButton,
            m_searchButton,
            m_hashButton,
            m_exportButton,
            m_importButton,
            m_compareButton,
            m_scanButton })
        {
            if (button != nullptr)
            {
                button->setEnabled(!busy);
            }
        }
        if (m_importButton != nullptr)
        {
            m_importButton->setEnabled(!busy && !m_readOnlyCheck->isChecked());
        }
    }
}

ks::ui::PageNavigationCatalog ks::misc::DiskEditorTab::navigationCatalog(const DiskEditorTab* existing)
{
    ks::ui::PageNavigationCatalog schema;
    for (const auto& definition : kDiskEditorTabNavigation)
        schema.append(ks::ui::PageNavigationTabDescriptor(definition));
    return existing ? existing->m_navigationTabs.describe(std::move(schema)) : schema;
}
QWidget* ks::misc::DiskEditorTab::activateNavigationDescriptor(const QString& id)
{
    return m_navigationTabs.activate(id, navigationCatalog(this));
}
namespace { const bool kDiskEditorTabNavigationRegistered =
    ks::ui::RegisterTypedPageNavigationCatalog<ks::misc::DiskEditorTab>(QStringLiteral("misc.disk_editor")); }
