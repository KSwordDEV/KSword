#include "LogDockWidget.h"
#include "../Internationalization/LanguageManager.h"
#include "../theme.h"
#include "../UI/FlatTableModel.h"
#include "../UI/TableInteractionSupport.h"
#include "../UI/VisibleTableWidget.h"

#include <algorithm>
#include <cstdint>
#include <limits>
#include <utility>

#include <QAction>
#include <QAbstractItemView>
#include <QAbstractItemModel>
#include <QApplication>
#include <QBrush>
#include <QCheckBox>
#include <QClipboard>
#include <QHash>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QInputDialog>
#include <QStyledItemDelegate>
#include <QStyle>
#include <QItemSelectionModel>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMessageBox>
#include <QPainter>
#include <QPen>
#include <QPixmap>
#include <QPointer>
#include <QPushButton>
#include <QScrollBar>
#include <QSize>
#include <QSpinBox>
#include <QStringList>
#include <QTableView>
#include <QTimer>
#include <QVBoxLayout>
#include <QSvgRenderer>

// Windows 下优先使用原生 shell 保存对话框（满足需求中的 explorer 场景）。
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <commdlg.h>
#pragma comment(lib, "Comdlg32.lib")
#endif

namespace
{
    using LogTableModel = ks::ui::FlatTableModel<kEvent>;

    // 表格列常量：确保同一语义在代码中统一引用。
    constexpr int LevelColumn = 0;      // 等级列（仅彩色方块，标题留空）。
    constexpr int TimeColumn = 1;       // 时间列。
    constexpr int ContentColumn = 2;    // 内容列。
    constexpr int FileColumn = 3;       // 文件列。
    constexpr int FunctionColumn = 4;   // 函数列。
    constexpr int TotalColumns = 5;     // 列总数。

    // 统一的资源路径常量，避免硬编码散落。
    constexpr const char* IconExportPath = ":/Icon/log_export.svg";
    constexpr const char* IconClearPath = ":/Icon/log_clear.svg";
    constexpr const char* IconCopyPath = ":/Icon/log_copy.svg";
    constexpr const char* IconClipboardPath = ":/Icon/log_clipboard.svg";
    constexpr const char* IconTrackPath = ":/Icon/log_track.svg";
    constexpr const char* IconCancelTrackPath = ":/Icon/log_cancel_track.svg";

    // LogContentWrapDelegate：
    // - 输入：日志表格模型索引和默认绘制 option；
    // - 处理：只允许内容/文件/函数这些长文本列换行，时间列和等级列保持单行；
    // - 返回：通过 sizeHint/paint 影响视图绘制，不改变模型数据。
    class LogContentWrapDelegate final : public QStyledItemDelegate
    {
    public:
        explicit LogContentWrapDelegate(QTableView* tableView)
            : QStyledItemDelegate(tableView)
            , m_tableView(tableView)
        {
        }

        void paint(QPainter* painter, const QStyleOptionViewItem& option, const QModelIndex& index) const override
        {
            QStyleOptionViewItem adjustedOption(option);
            const bool rowSelected = (adjustedOption.state & QStyle::State_Selected) != 0;
            initStyleOption(&adjustedOption, index);
            adjustedOption.textElideMode = isWrappingColumn(index.column()) ? Qt::ElideNone : Qt::ElideRight;
            adjustedOption.features.setFlag(QStyleOptionViewItem::WrapText, isWrappingColumn(index.column()));
            adjustedOption.state &= ~QStyle::State_Selected;
            adjustedOption.state &= ~QStyle::State_HasFocus;
            QStyledItemDelegate::paint(painter, adjustedOption, index);
            if (rowSelected)
            {
                drawRowSelectionOutline(painter, option, index);
            }
        }

        QSize sizeHint(const QStyleOptionViewItem& option, const QModelIndex& index) const override
        {
            if (!isWrappingColumn(index.column()))
            {
                QSize baseSize = QStyledItemDelegate::sizeHint(option, index);
                baseSize.setHeight(24);
                return baseSize;
            }

            QStyleOptionViewItem adjustedOption(option);
            initStyleOption(&adjustedOption, index);
            adjustedOption.textElideMode = Qt::ElideNone;
            adjustedOption.features.setFlag(QStyleOptionViewItem::WrapText, true);
            QSize baseSize = QStyledItemDelegate::sizeHint(adjustedOption, index);
            baseSize.setHeight(std::clamp(baseSize.height(), 24, 120));
            return baseSize;
        }

    private:
        void drawRowSelectionOutline(
            QPainter* painter,
            const QStyleOptionViewItem& option,
            const QModelIndex& index) const
        {
            if (painter == nullptr || m_tableView == nullptr || !index.isValid())
            {
                return;
            }

            QHeaderView* headerView = m_tableView->horizontalHeader();
            const QAbstractItemModel* model = index.model();
            if (headerView == nullptr || model == nullptr)
            {
                return;
            }

            int firstVisibleVisualIndex = std::numeric_limits<int>::max();
            int lastVisibleVisualIndex = std::numeric_limits<int>::min();
            const int columnCount = model->columnCount(index.parent());
            for (int columnIndex = 0; columnIndex < columnCount; ++columnIndex)
            {
                if (m_tableView->isColumnHidden(columnIndex))
                {
                    continue;
                }

                const int visualIndex = headerView->visualIndex(columnIndex);
                if (visualIndex < 0)
                {
                    continue;
                }
                firstVisibleVisualIndex = std::min(firstVisibleVisualIndex, visualIndex);
                lastVisibleVisualIndex = std::max(lastVisibleVisualIndex, visualIndex);
            }

            const int currentVisualIndex = headerView->visualIndex(index.column());
            if (currentVisualIndex < 0 ||
                firstVisibleVisualIndex == std::numeric_limits<int>::max() ||
                lastVisibleVisualIndex == std::numeric_limits<int>::min())
            {
                return;
            }

            const QRect borderRect = option.rect.adjusted(0, 1, -1, -2);
            if (!borderRect.isValid())
            {
                return;
            }

            painter->save();
            painter->setRenderHint(QPainter::Antialiasing, false);
            painter->setBrush(Qt::NoBrush);
            painter->setPen(QPen(KswordTheme::PrimaryBlueColor, 3.0));
            painter->drawLine(borderRect.topLeft(), borderRect.topRight());
            painter->drawLine(borderRect.bottomLeft(), borderRect.bottomRight());
            if (currentVisualIndex == firstVisibleVisualIndex)
            {
                painter->drawLine(borderRect.topLeft(), borderRect.bottomLeft());
            }
            if (currentVisualIndex == lastVisibleVisualIndex)
            {
                painter->drawLine(borderRect.topRight(), borderRect.bottomRight());
            }
            painter->restore();
        }

        static bool isWrappingColumn(const int column)
        {
            return column == ContentColumn || column == FileColumn || column == FunctionColumn;
        }

        QPointer<QTableView> m_tableView;
    };

    // DefaultButtonIconSize：日志面板按钮与菜单图标默认尺寸。
    constexpr QSize DefaultButtonIconSize(16, 16);
    constexpr int ActionButtonExtent = 28; // ActionButtonExtent：顶部图标按钮边长（像素）。
    constexpr int DefaultVisibleLogLimit = 200;  // 默认只把最近 200 条日志渲染到 UI，降低 Dock 刷新压力。
    constexpr int MinVisibleLogLimit = 1;        // 最小允许显示 1 条，避免“条数”控件出现不直观的隐藏下限。
    constexpr int MaxVisibleLogLimit = 10000;    // 最大值保留诊断弹性，同时限制极端行数拖垮表格绘制。

    // logRowKey 作用：
    // - 把日志管理器分配的单调序号转换为 FlatTableModel 所需的稳定行键；
    // - 让新增日志走 insert/remove/layout 变更，而不是 beginResetModel/endResetModel。
    // 参数 logItem：已归档并带唯一 recordSequence 的日志记录。
    // 返回值：该日志记录的全局唯一字符串键。
    std::string logRowKey(const kEvent& logItem)
    {
        return std::to_string(logItem.recordSequence);
    }

    // createBlueThemedIcon 作用：
    // - 把 qrc 中的单色 SVG 图标重新着色为主题蓝色；
    // - 避免修改原始 SVG 文件，实现运行时统一换色。
    // 参数 resourcePath：qrc 资源路径（如 :/Icon/log_copy.svg）。
    // 参数 iconSize：输出图标尺寸。
    // 返回值：重着色后的 QIcon；若渲染失败则回退原图标。
    QIcon createBlueThemedIcon(const char* resourcePath, const QSize& iconSize = DefaultButtonIconSize)
    {
        const QString iconPath = QString::fromUtf8(resourcePath);

        // 使用 Qt SVG 渲染器把矢量图绘制到透明像素缓冲。
        QSvgRenderer svgRenderer(iconPath);
        if (!svgRenderer.isValid())
        {
            // 资源异常时回退默认图标，避免功能不可见。
            return QIcon(iconPath);
        }

        QPixmap tintedPixmap(iconSize);
        tintedPixmap.fill(Qt::transparent);

        // 第一步先渲染原 SVG；第二步用 SourceIn 把非透明像素统一染成主题蓝。
        QPainter painter(&tintedPixmap);
        painter.setRenderHint(QPainter::Antialiasing, true);
        svgRenderer.render(&painter, QRectF(0, 0, iconSize.width(), iconSize.height()));
        painter.setCompositionMode(QPainter::CompositionMode_SourceIn);
        painter.fillRect(tintedPixmap.rect(), KswordTheme::PrimaryBlueColor);
        painter.end();

        return QIcon(tintedPixmap);
    }

    // buildBlueCheckBoxStyleSheet 作用：
    // - 生成日志面板统一复选框蓝色样式（文字/边框/选中态）。
    // 返回值：QSS 字符串。
    QString buildBlueCheckBoxStyleSheet()
    {
        return QStringLiteral(
            "QCheckBox {"
            "  color: %1;"
            "  spacing: 6px;"
            "}")
            .arg(KswordTheme::TextPrimaryHex());
    }

    // buildBlueButtonStyleSheet 作用：
    // - 生成日志面板图标按钮透明背景样式；
    // - 默认背景透明，仅在 hover/pressed 时给轻量高亮。
    // 返回值：QSS 字符串。
    QString buildBlueButtonStyleSheet()
    {
        return QStringLiteral(
            "QPushButton {"
            "  color: %1;"
            "  background: transparent;"
            "  border: 1px solid transparent;"
            "  border-radius: 4px;"
            "  padding: 4px;"
            "}"
            "QPushButton:hover {"
            "  background: %2;"
            "  border: 1px solid %3;"
            "}"
            "QPushButton:pressed {"
            "  background: %4;"
            "  border: 1px solid %5;"
            "}")
            .arg(KswordTheme::TextPrimaryHex())
            .arg(KswordTheme::RgbaColorName(KswordTheme::AccentColor(KswordTheme::AccentRole::Blue), 28))
            .arg(KswordTheme::RgbaColorName(KswordTheme::AccentColor(KswordTheme::AccentRole::Blue), 96))
            .arg(KswordTheme::RgbaColorName(KswordTheme::AccentColor(KswordTheme::AccentRole::Blue), 46))
            .arg(KswordTheme::RgbaColorName(KswordTheme::AccentColor(KswordTheme::AccentRole::Blue), 136));
    }

    // buildBlueHeaderStyleSheet 作用：
    // - 统一日志表格头部文本为主题蓝色。
    // 返回值：QHeaderView section 样式字符串。
    QString buildBlueHeaderStyleSheet()
    {
        return QStringLiteral(
            "QHeaderView::section {"
            "  color: %1;"
            "  background: transparent; /* %2 */"
            "  border: 1px solid %3;"
            "  padding: 4px;"
            "  font-weight: 600;"
            "}")
            .arg(KswordTheme::PrimaryBlueHex)
            .arg(KswordTheme::SurfaceHex())
            .arg(KswordTheme::BorderHex());
    }

    // buildBlueInputStyleSheet 作用：
    // - 生成日志工具栏里数字输入框/标签的主题样式；
    // - 显式指定背景、前景和 hover/focus 边框，避免深色模式下继承到浅色白块；
    // - 返回值：可直接应用到 QSpinBox/QLabel 的 QSS 字符串。
    QString buildBlueInputStyleSheet()
    {
        return QStringLiteral(
            "QSpinBox {"
            "  color: %3;"
            "  background: %2;"
            "  border: 1px solid %1;"
            "  border-radius: 3px;"
            "  padding: 2px 6px;"
            "}"
            "QSpinBox:hover, QSpinBox:focus {"
            "  border: 1px solid %4;"
            "}"
            // 步进按钮不在这里覆写：全局基线已经给出带箭头、带 hover/到限反馈的
            // 完整实现，本地再改成透明无边框只会退回“看不出是按钮”的样子。
            "QLabel {"
            "  color: %3;"
            "}")
            .arg(KswordTheme::BorderHex())
            .arg(KswordTheme::SurfaceHex())
            .arg(KswordTheme::TextPrimaryHex())
            .arg(KswordTheme::PrimaryBlueHex);
    }
}

LogDockWidget::LogDockWidget(QWidget* parent)
    : QWidget(parent)
{
    // 构造阶段按照“UI -> 信号 -> 刷新器”的顺序初始化，便于维护。
    initializeUi();
    initializeConnections();
    initializeRefreshTimer();

    // 首次显示前先强制刷新一次，确保打开 Dock 即可看到已有日志。
    refreshTableFromManager(true);
}

void LogDockWidget::refreshNow()
{
    refreshTableFromManager(true);
}

void LogDockWidget::initializeUi()
{
    // 根布局：上下排列两层（单行工具栏 + 表格）。
    m_rootLayout = new QVBoxLayout(this);
    m_rootLayout->setContentsMargins(0, 0, 0, 0);
    m_rootLayout->setSpacing(4);

    // 单行工具栏：
    // - 三个动作按钮与全部过滤/状态复选框全部放在同一行；
    // - 满足“所有复选框和按钮全部堆到一行”的布局要求。
    m_actionLayout = new QHBoxLayout();
    m_actionLayout->setContentsMargins(6, 6, 6, 4);
    m_actionLayout->setSpacing(6);

    m_exportButton = new QPushButton(createBlueThemedIcon(IconExportPath), QString(), this);
    m_clearButton = new QPushButton(createBlueThemedIcon(IconClearPath), QString(), this);
    m_copyVisibleButton = new QPushButton(createBlueThemedIcon(IconCopyPath), QString(), this);
    m_debugCheck = new QCheckBox("Debug", this);
    m_infoCheck = new QCheckBox("Info", this);
    m_warnCheck = new QCheckBox("Warn", this);
    m_errorCheck = new QCheckBox("Error", this);
    m_fatalCheck = new QCheckBox("Fatal", this);
    m_detailCheck = new QCheckBox("详细信息", this);
    m_autoScrollCheck = new QCheckBox("保持滚动到最底端", this);
    m_visibleLimitSpin = new QSpinBox(this);

    // 最近日志条数：
    // - 只限制 QTableView 中实际渲染的行数，避免日志风暴时图形界面被成千上万行拖死；
    // - 不截断 KswordARKEventEntry 内部历史，因此用户把 200 改成 1000 后会立刻从旧日志中补齐。
    m_visibleLimitSpin->setRange(MinVisibleLogLimit, MaxVisibleLogLimit);
    m_visibleLimitSpin->setSingleStep(100);
    m_visibleLimitSpin->setValue(DefaultVisibleLogLimit);
    m_visibleLimitSpin->setSuffix(QStringLiteral(" 条"));
    m_visibleLimitSpin->setKeyboardTracking(false);
    m_visibleLimitSpin->setMaximumWidth(96);

    // 按钮均设置图标与提示，满足“尽量用图标 + 悬停说明功能”。
    m_exportButton->setToolTip("导出全部日志到 .txt 文件");
    m_clearButton->setToolTip("清空日志管理器中的全部日志（双重确认）");
    m_copyVisibleButton->setToolTip("复制当前可见列表内容（支持追踪过滤状态）");
    m_detailCheck->setToolTip("显示文件列和函数列");
    m_autoScrollCheck->setToolTip("开启后表格刷新将自动滚动到最后一行");
    m_visibleLimitSpin->setToolTip("限制界面显示的最近日志条数；提高上限可显示更早记录。");

    ks::i18n::LanguageManager& languageManager = ks::i18n::LanguageManager::instance();
    languageManager.bindText(m_debugCheck, QStringLiteral("log.level.debug"), QStringLiteral("Debug"));
    languageManager.bindText(m_infoCheck, QStringLiteral("log.level.info"), QStringLiteral("Info"));
    languageManager.bindText(m_warnCheck, QStringLiteral("log.level.warn"), QStringLiteral("Warn"));
    languageManager.bindText(m_errorCheck, QStringLiteral("log.level.error"), QStringLiteral("Error"));
    languageManager.bindText(m_fatalCheck, QStringLiteral("log.level.fatal"), QStringLiteral("Fatal"));
    languageManager.bindText(m_detailCheck, QStringLiteral("log.detail"), QStringLiteral("详细信息"));
    languageManager.bindText(m_autoScrollCheck, QStringLiteral("log.autoscroll"), QStringLiteral("保持滚动到最底端"));
    languageManager.bindSuffix(
        m_visibleLimitSpin,
        QStringLiteral("log.suffix.entries"),
        QStringLiteral(" 条"));
    languageManager.bindToolTip(m_exportButton, QStringLiteral("log.tooltip.export"), QStringLiteral("导出全部日志到 .txt 文件"));
    languageManager.bindToolTip(m_clearButton, QStringLiteral("log.tooltip.clear"), QStringLiteral("清空日志管理器中的全部日志（双重确认）"));
    languageManager.bindToolTip(m_copyVisibleButton, QStringLiteral("log.tooltip.copy_visible"), QStringLiteral("复制当前可见列表内容（支持追踪过滤状态）"));
    languageManager.bindToolTip(m_detailCheck, QStringLiteral("log.tooltip.detail"), QStringLiteral("显示文件列和函数列"));
    languageManager.bindToolTip(m_autoScrollCheck, QStringLiteral("log.tooltip.autoscroll"), QStringLiteral("开启后表格刷新将自动滚动到最后一行"));
    languageManager.bindToolTip(m_visibleLimitSpin, QStringLiteral("log.tooltip.visible_limit"), QStringLiteral("限制界面显示的最近日志条数；提高上限可显示更早记录。"));

    // 图标尺寸与按钮尺寸统一，保证工具栏视觉紧凑并保持纯图标风格。
    m_exportButton->setIconSize(DefaultButtonIconSize);
    m_clearButton->setIconSize(DefaultButtonIconSize);
    m_copyVisibleButton->setIconSize(DefaultButtonIconSize);
    m_exportButton->setFixedSize(ActionButtonExtent, ActionButtonExtent);
    m_clearButton->setFixedSize(ActionButtonExtent, ActionButtonExtent);
    m_copyVisibleButton->setFixedSize(ActionButtonExtent, ActionButtonExtent);
    m_exportButton->setCursor(Qt::PointingHandCursor);
    m_clearButton->setCursor(Qt::PointingHandCursor);
    m_copyVisibleButton->setCursor(Qt::PointingHandCursor);
    m_autoScrollCheck->setChecked(true);

    // 把日志区按钮背景改为透明，仅保留图标与悬停反馈。
    const QString blueButtonStyle = buildBlueButtonStyleSheet();
    m_exportButton->setStyleSheet(blueButtonStyle);
    m_clearButton->setStyleSheet(blueButtonStyle);
    m_copyVisibleButton->setStyleSheet(blueButtonStyle);

    // 把复选框文字与指示器统一改为欢迎页同款蓝色。
    const QString blueCheckBoxStyle = buildBlueCheckBoxStyleSheet();
    m_debugCheck->setStyleSheet(blueCheckBoxStyle);
    m_infoCheck->setStyleSheet(blueCheckBoxStyle);
    m_warnCheck->setStyleSheet(blueCheckBoxStyle);
    m_errorCheck->setStyleSheet(blueCheckBoxStyle);
    m_fatalCheck->setStyleSheet(blueCheckBoxStyle);
    m_detailCheck->setStyleSheet(blueCheckBoxStyle);
    m_autoScrollCheck->setStyleSheet(blueCheckBoxStyle);
    m_visibleLimitSpin->setStyleSheet(buildBlueInputStyleSheet());

    // Debug 默认关闭：避免日志输出 Dock 首次打开时被调试级别噪声淹没。
    m_debugCheck->setChecked(false);
    m_infoCheck->setChecked(true);
    m_warnCheck->setChecked(true);
    m_errorCheck->setChecked(true);
    m_fatalCheck->setChecked(true);
    m_actionLayout->addWidget(m_exportButton);
    m_actionLayout->addWidget(m_clearButton);
    m_actionLayout->addWidget(m_copyVisibleButton);
    m_actionLayout->addSpacing(8);
    m_actionLayout->addWidget(m_debugCheck);
    m_actionLayout->addWidget(m_infoCheck);
    m_actionLayout->addWidget(m_warnCheck);
    m_actionLayout->addWidget(m_errorCheck);
    m_actionLayout->addWidget(m_fatalCheck);
    m_actionLayout->addWidget(m_detailCheck);
    m_actionLayout->addWidget(m_autoScrollCheck);
    m_actionLayout->addSpacing(8);

    QLabel* visibleLimitLabel = new QLabel(QStringLiteral("展示最近日志条数:"), this);
    languageManager.bindText(visibleLimitLabel, QStringLiteral("log.label.visible_limit"), QStringLiteral("展示最近日志条数:"));
    visibleLimitLabel->setToolTip(m_visibleLimitSpin->toolTip());
    visibleLimitLabel->setStyleSheet(buildBlueInputStyleSheet());
    m_actionLayout->addWidget(visibleLimitLabel);
    m_actionLayout->addWidget(m_visibleLimitSpin);
    m_actionLayout->addStretch(1);

    // 第三层：日志表格，要求不可编辑且占满 Dock。
    // 选择策略：
    // - SelectRows 让单击任意单元格时选中整行；
    // - ExtendedSelection 支持 Ctrl+单击叠加多行选择；
    // - 后续右键菜单会根据多选状态限制为“复制”动作。
    // 性能策略：
    // - QTableView 只负责可视化；
    // - FlatTableModel 保存当前可见 kEvent 快照，并按需返回单元格数据；
    // - 避免每次刷新为 rows * columns 创建/销毁 QTableWidgetItem。
    std::vector<LogTableModel::ColumnSpec> logColumns;
    logColumns.reserve(TotalColumns);
    logColumns.push_back({ QString(), Qt::AlignCenter });
    logColumns.push_back({ QStringLiteral("时间"), Qt::AlignCenter });
    logColumns.push_back({ QStringLiteral("内容"), Qt::AlignLeft | Qt::AlignVCenter });
    logColumns.push_back({ QStringLiteral("文件"), Qt::AlignLeft | Qt::AlignVCenter });
    logColumns.push_back({ QStringLiteral("函数"), Qt::AlignLeft | Qt::AlignVCenter });

    m_logModel = new LogTableModel(
        std::move(logColumns),
        [this](const kEvent& logItem, const int column, const int role) {
            return resolveLogTableData(logItem, column, role);
        },
        this,
        LogTableModel::FlagsResolver(),
        logRowKey);

    m_logTable = new ks::ui::TableActionTableView(this);
    m_logTable->setModel(m_logModel);
    m_logTable->setItemDelegate(new LogContentWrapDelegate(m_logTable));
    m_logTable->setProperty("ksword_preserve_custom_table_delegate", true);
    m_logTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_logTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_logTable->setSelectionMode(QAbstractItemView::ExtendedSelection);
    m_logTable->setContextMenuPolicy(Qt::CustomContextMenu);
    m_logTable->setWordWrap(true);
    m_logTable->setShowGrid(true);
    m_logTable->setAlternatingRowColors(false);
    m_logTable->setSortingEnabled(false);
    m_logTable->setTextElideMode(Qt::ElideNone);

    // 表格头部策略：等级列固定宽度，其余列可交互拖动。
    QHeaderView* horizontalHeader = m_logTable->horizontalHeader();
    horizontalHeader->setSectionResizeMode(LevelColumn, QHeaderView::Fixed);
    horizontalHeader->setSectionResizeMode(TimeColumn, QHeaderView::Interactive);
    horizontalHeader->setSectionResizeMode(ContentColumn, QHeaderView::Stretch);
    horizontalHeader->setSectionResizeMode(FileColumn, QHeaderView::Interactive);
    horizontalHeader->setSectionResizeMode(FunctionColumn, QHeaderView::Interactive);
    horizontalHeader->setStretchLastSection(false);
    horizontalHeader->setStyleSheet(buildBlueHeaderStyleSheet());
    horizontalHeader->setVisible(false);

    // 等级列只容纳彩色方块，因此锁定窄列宽。
    m_logTable->setColumnWidth(LevelColumn, 24);
    m_logTable->setColumnWidth(TimeColumn, 170);
    m_logTable->setColumnWidth(ContentColumn, 320);
    m_logTable->setColumnWidth(FileColumn, 240);
    m_logTable->setColumnWidth(FunctionColumn, 320);
    m_logTable->verticalHeader()->setVisible(false);
    m_logTable->verticalHeader()->setDefaultSectionSize(28);
    m_logTable->verticalHeader()->setMinimumSectionSize(24);
    m_logTable->verticalHeader()->setMaximumSectionSize(120);
    // 长日志只测量当前视口内的可变行高；滚动后再按需测量新出现的行。
    // 模型仍持有完整日志快照，过滤/复制等全量逻辑不受影响。
    ks::ui::InstallVisibleRowHeightRefresh(m_logTable);

    // 默认关闭详细信息模式，仅显示等级/时间/内容。
    applyDetailColumnVisibility();

    // 最后拼装两层布局。
    m_rootLayout->addLayout(m_actionLayout);
    m_rootLayout->addWidget(m_logTable, 1);
}

void LogDockWidget::initializeConnections()
{
    // 按钮动作连接：导出/清空/复制可见。
    connect(m_exportButton, &QPushButton::clicked, this, [this]() { exportAllLogs(); });
    connect(m_clearButton, &QPushButton::clicked, this, [this]() { clearAllLogsWithDoubleConfirm(); });
    connect(m_copyVisibleButton, &QPushButton::clicked, this, [this]() { copyVisibleRows(); });

    // 详细信息开关只切列可见性，不需要整表重建。
    connect(m_detailCheck, &QCheckBox::toggled, this, [this]() { applyDetailColumnVisibility(); });

    // 五个等级复选框任意变化时都强制刷新表格。
    connect(m_debugCheck, &QCheckBox::toggled, this, [this]() { refreshTableFromManager(true); });
    connect(m_infoCheck, &QCheckBox::toggled, this, [this]() { refreshTableFromManager(true); });
    connect(m_warnCheck, &QCheckBox::toggled, this, [this]() { refreshTableFromManager(true); });
    connect(m_errorCheck, &QCheckBox::toggled, this, [this]() { refreshTableFromManager(true); });
    connect(m_fatalCheck, &QCheckBox::toggled, this, [this]() { refreshTableFromManager(true); });
    connect(m_visibleLimitSpin, QOverload<int>::of(&QSpinBox::valueChanged), this, [this](const int) {
        // 用户调大显示条数时必须立即从内部全量历史里补旧日志；
        // 因此这里强制刷新，即使日志 revision 没有变化也要重建可见快照。
        refreshTableFromManager(true);
    });

    // 右键菜单连接。
    connect(m_logTable, &QWidget::customContextMenuRequested, this, [this](const QPoint& position) {
        showTableContextMenu(position);
    });
}

void LogDockWidget::applyDetailColumnVisibility()
{
    if (m_logTable == nullptr)
    {
        return;
    }

    // detailVisible 用途：记录“详细信息”开关当前状态，决定附加列是否显示。
    const bool detailVisible = (m_detailCheck != nullptr) && m_detailCheck->isChecked();
    m_logTable->setColumnHidden(FileColumn, !detailVisible);
    m_logTable->setColumnHidden(FunctionColumn, !detailVisible);
}

void LogDockWidget::initializeRefreshTimer()
{
    // 周期刷新间隔 250ms：实时性与性能折中。
    m_refreshTimer = new QTimer(this);
    m_refreshTimer->setInterval(250);

    // 非强制刷新：仅 revision 变化时重建 UI。
    connect(m_refreshTimer, &QTimer::timeout, this, [this]() {
        refreshTableFromManager(false);
    });
    m_refreshTimer->start();
}

void LogDockWidget::refreshTableFromManager(const bool forceRefresh)
{
    // 右键菜单处于 exec 嵌套事件循环时，模型 reset 会让菜单记录的行号失效。
    // 同类刷新只保留最新一次，菜单关闭后再回投，保证复制/跟踪仍针对右键时的日志行。
    const QPointer<LogDockWidget> safeThis(this);
    const QString refreshCommitKey = forceRefresh
        ? QStringLiteral("log-table-force-refresh")
        : QStringLiteral("log-table-periodic-refresh");
    if (ks::ui::DeferTableUiCommitIfContextMenuOpen(
        this,
        refreshCommitKey,
        { m_logTable },
        [safeThis, forceRefresh]()
        {
            if (!safeThis.isNull())
            {
                safeThis->refreshTableFromManager(forceRefresh);
            }
        }))
    {
        return;
    }

    const std::size_t currentRevision = KswordARKEventEntry.Revision();
    if (!forceRefresh && currentRevision == m_lastRevision)
    {
        return;
    }
    m_lastRevision = currentRevision;

    // 从全局日志管理器读取“最近 N 条匹配日志”而不是完整快照：
    // - KswordARKEventEntry 内部仍然保留全量历史，导出/清空行为不变；
    // - UI 只拿当前等级/GUID 筛选后的最近 visibleLogLimit() 条，避免表格模型和行高计算被海量日志拖死；
    // - 用户把 200 调大到 1000 时，这里会重新扫描内部历史并立刻补齐之前已经记录的日志。
    std::uint32_t enabledLevelMask = 0;
    for (const kLogLevel level : {
        kLogLevel::Debug,
        kLogLevel::Info,
        kLogLevel::Warn,
        kLogLevel::Error,
        kLogLevel::Fatal })
    {
        if (isLevelEnabledByCheckbox(level))
        {
            enabledLevelMask |= (std::uint32_t{ 1 } << static_cast<unsigned int>(level));
        }
    }

    // filteredEvents 之后交给模型持有；复制与追踪逻辑通过 visibleEvents()/visibleEventAt() 读取模型快照。
    std::vector<kEvent> filteredEvents = KswordARKEventEntry.SnapshotRecent(
        static_cast<std::size_t>(visibleLogLimit()),
        enabledLevelMask,
        m_isTracking ? &m_trackingGuid : nullptr);
    rebuildTable(std::move(filteredEvents));
}

void LogDockWidget::rebuildTable(std::vector<kEvent> filteredEvents)
{
    if (m_logTable == nullptr || m_logModel == nullptr)
    {
        return;
    }

    // 若未开启自动滚动，先记住滚动条位置，刷新后恢复。
    const int previousScrollValue = m_logTable->verticalScrollBar()->value();

    // 每条归档日志都有唯一序号，因此 setRows 会按键发布增量插入/删除及布局调整。
    // Qt 会随模型信号保留仍然可见行的选择、当前索引和持久索引，无需手动按内容反查。
    m_logModel->setRows(std::move(filteredEvents));
    ks::ui::RefreshVisibleRowHeights(m_logTable);

    // 根据“保持滚动到底端”开关决定刷新后的滚动行为。
    if (m_autoScrollCheck->isChecked())
    {
        m_logTable->scrollToBottom();
    }
    else
    {
        m_logTable->verticalScrollBar()->setValue(previousScrollValue);
    }
}

int LogDockWidget::visibleLogLimit() const
{
    // UI 构造早期或单元测试环境下数字框可能为空；此时回退默认值。
    // 返回值只用于限制界面渲染数量，不参与 KswordARKEventEntry 的内部存储裁剪。
    if (m_visibleLimitSpin == nullptr)
    {
        return DefaultVisibleLogLimit;
    }

    return std::clamp(m_visibleLimitSpin->value(), MinVisibleLogLimit, MaxVisibleLogLimit);
}

QVariant LogDockWidget::resolveLogTableData(const kEvent& logItem, const int column, const int role) const
{
    // DecorationRole 只用于等级列：界面保持原来的“彩色小方块”风格。
    if (role == Qt::DecorationRole && column == LevelColumn)
    {
        return makeLevelSquareIcon(getLevelColor(logItem.level));
    }

    // Error/Fatal 的整行着色从 QTableWidgetItem 属性迁移为模型 role。
    if (role == Qt::BackgroundRole || role == Qt::ForegroundRole)
    {
        return getRowHighlightBrush(logItem, role);
    }

    // ToolTipRole 保留原行为：等级列给文字说明，长文本列给完整内容提示。
    if (role == Qt::ToolTipRole)
    {
        switch (column)
        {
        case LevelColumn:
            return getLevelText(logItem.level);
        case ContentColumn:
            return QString::fromStdString(logItem.content);
        case FileColumn:
            return QString::fromStdString(logItem.fileLocation);
        case FunctionColumn:
            return QString::fromStdString(logItem.functionName);
        default:
            return {};
        }
    }

    if (role != Qt::DisplayRole)
    {
        return {};
    }

    // DisplayRole 只返回界面真正显示的文字；等级列视觉上保持为空。
    switch (column)
    {
    case LevelColumn:
        return QString();
    case TimeColumn:
        return QString::fromStdString(FormatTimeToString(logItem.timestamp));
    case ContentColumn:
        return QString::fromStdString(logItem.content);
    case FileColumn:
        return QString::fromStdString(logItem.fileLocation);
    case FunctionColumn:
        return QString::fromStdString(logItem.functionName);
    default:
        return {};
    }
}

QVariant LogDockWidget::getRowHighlightBrush(const kEvent& logItem, const int role) const
{
    if (role != Qt::BackgroundRole && role != Qt::ForegroundRole)
    {
        return {};
    }

    // 默认情况下不改变行配色，仅 Error/Fatal 特殊着色。
    if (logItem.level == kLogLevel::Fatal)
    {
        return role == Qt::BackgroundRole
            ? QVariant(QBrush(KswordTheme::BlackColor()))
            : QVariant(QBrush(KswordTheme::WhiteColor()));
    }

    if (logItem.level == kLogLevel::Error)
    {
        const QColor rowBackground = KswordTheme::ErrorBackgroundColor();
        return role == Qt::BackgroundRole
            ? QVariant(QBrush(rowBackground))
            : QVariant(QBrush(KswordTheme::OnAccentColor()));
    }

    return {};
}

QIcon LogDockWidget::makeLevelSquareIcon(const QColor& color) const
{
    // Model/View 绘制时 DecorationRole 可能被重复请求。
    // 以最终 RGBA 颜色为 key 缓存小图标，避免每次 paint 都重新分配 QPixmap 并跑 QPainter。
    static QHash<QRgb, QIcon> levelIconCache;
    const QRgb cacheKey = color.rgba();
    const auto cachedIcon = levelIconCache.constFind(cacheKey);
    if (cachedIcon != levelIconCache.constEnd())
    {
        return cachedIcon.value();
    }

    // 使用 QPainter 在透明底图上绘制纯色小方块。
    QPixmap squarePixmap(12, 12);
    squarePixmap.fill(Qt::transparent);

    QPainter painter(&squarePixmap);
    painter.setRenderHint(QPainter::Antialiasing, true);
    painter.setPen(Qt::NoPen);
    painter.setBrush(color);
    painter.drawRect(1, 1, 10, 10);

    const QIcon squareIcon(squarePixmap);
    levelIconCache.insert(cacheKey, squareIcon);
    return squareIcon;
}

QColor LogDockWidget::getLevelColor(const kLogLevel level) const
{
    switch (level)
    {
    case kLogLevel::Debug:
        return KswordTheme::AccentColor(KswordTheme::AccentRole::Blue, -12, -38);
    case kLogLevel::Info:
        return KswordTheme::SuccessColor();
    case kLogLevel::Warn:
        return KswordTheme::WarningColor();
    case kLogLevel::Error:
        return KswordTheme::ErrorColor();
    case kLogLevel::Fatal:
        return KswordTheme::AccentTextColor(KswordTheme::AccentRole::Red, KswordTheme::BlackColor());
    default:
        return KswordTheme::TextDisabledColor();
    }
}

QString LogDockWidget::getLevelText(const kLogLevel level) const
{
    return QString::fromStdString(LogLevelToString(level));
}

bool LogDockWidget::isLevelEnabledByCheckbox(const kLogLevel level) const
{
    switch (level)
    {
    case kLogLevel::Debug:
        return m_debugCheck->isChecked();
    case kLogLevel::Info:
        return m_infoCheck->isChecked();
    case kLogLevel::Warn:
        return m_warnCheck->isChecked();
    case kLogLevel::Error:
        return m_errorCheck->isChecked();
    case kLogLevel::Fatal:
        return m_fatalCheck->isChecked();
    default:
        return true;
    }
}

void LogDockWidget::showTableContextMenu(const QPoint& position)
{
    if (m_logTable == nullptr)
    {
        return;
    }

    // 通过右键位置定位行列，若点在空白区域 row/column 为 -1。
    int row = -1;
    int column = -1;
    const QModelIndex clickedIndex = m_logTable->indexAt(position);
    if (clickedIndex.isValid())
    {
        row = clickedIndex.row();
        column = clickedIndex.column();
    }

    // selectedRowIndexes 用途：记录右键弹出前表格已有选中行。
    // 如果用户 Ctrl+单击选中了多行，则右键菜单必须只保留“复制”。
    std::vector<int> selectedRowIndexes = collectSelectedRowIndexes();
    const bool clickedRowIsSelected =
        std::find(selectedRowIndexes.cbegin(), selectedRowIndexes.cend(), row) != selectedRowIndexes.cend();

    // 右键点到未选中行时，按常见表格行为切换到该单行。
    // 这样普通右键不会误操作之前 Ctrl 多选留下的行集合。
    const bool hasValidCell = row >= 0 && column >= 0 && visibleEventAt(row) != nullptr;
    if (hasValidCell && !clickedRowIsSelected)
    {
        m_logTable->clearSelection();
        m_logTable->selectRow(row);
        selectedRowIndexes.clear();
        selectedRowIndexes.push_back(row);
    }

    QMenu contextMenu(this);
    contextMenu.setStyleSheet(KswordTheme::ContextMenuStyle());

    // 多行选择场景：
    // - 菜单只出现“复制”；
    // - 复制范围固定为所有选中行，避免跟踪/单元格复制造成歧义。
    if (selectedRowIndexes.size() > 1)
    {
        QAction* copySelectedRowsAction = contextMenu.addAction(
            createBlueThemedIcon(IconCopyPath),
            ks::i18n::contextText(QStringLiteral("log.menu.copy"), QStringLiteral("复制")));
        copySelectedRowsAction->setEnabled(!selectedRowIndexes.empty());

        QAction* selectedAction = contextMenu.exec(m_logTable->viewport()->mapToGlobal(position));
        if (selectedAction == copySelectedRowsAction)
        {
            copySelectedRows();
        }
        return;
    }

    QAction* copyCellAction = contextMenu.addAction(
        createBlueThemedIcon(IconCopyPath),
        ks::i18n::contextText(QStringLiteral("log.menu.copy_cell"), QStringLiteral("复制单元格")));
    QAction* copyRowAction = contextMenu.addAction(
        createBlueThemedIcon(IconClipboardPath),
        ks::i18n::contextText(QStringLiteral("log.menu.copy_row"), QStringLiteral("复制行")));

    // 若未点中有效单元格，则复制操作不可用。
    copyCellAction->setEnabled(hasValidCell);
    copyRowAction->setEnabled(hasValidCell);

    // 第三个动作按状态切换为“跟踪事件”或“取消追踪”。
    QAction* trackAction = nullptr;
    if (m_isTracking)
    {
        trackAction = contextMenu.addAction(
            createBlueThemedIcon(IconCancelTrackPath),
            ks::i18n::contextText(QStringLiteral("log.menu.cancel_track"), QStringLiteral("取消追踪")));
    }
    else
    {
        trackAction = contextMenu.addAction(
            createBlueThemedIcon(IconTrackPath),
            ks::i18n::contextText(QStringLiteral("log.menu.track"), QStringLiteral("跟踪事件")));
        trackAction->setEnabled(hasValidCell);
    }

    QAction* selectedAction = contextMenu.exec(m_logTable->viewport()->mapToGlobal(position));
    if (selectedAction == nullptr)
    {
        return;
    }

    if (selectedAction == copyCellAction)
    {
        copySingleCell(row, column);
        return;
    }
    if (selectedAction == copyRowAction)
    {
        copySingleRow(row);
        return;
    }
    if (selectedAction == trackAction)
    {
        if (m_isTracking)
        {
            cancelTracking();
        }
        else
        {
            startTrackingByRow(row);
        }
    }
}

void LogDockWidget::copySingleCell(const int row, const int column)
{
    const kEvent* logItem = visibleEventAt(row);
    if (logItem == nullptr || column < 0)
    {
        return;
    }

    QString textToCopy;
    if (column == LevelColumn)
    {
        // 等级列视觉上只有彩色方块，复制时补充等级文本。
        textToCopy = getLevelText(logItem->level);
    }
    else
    {
        switch (column)
        {
        case TimeColumn:
            textToCopy = QString::fromStdString(FormatTimeToString(logItem->timestamp));
            break;
        case ContentColumn:
            textToCopy = QString::fromStdString(logItem->content);
            break;
        case FileColumn:
            textToCopy = QString::fromStdString(logItem->fileLocation);
            break;
        case FunctionColumn:
            textToCopy = QString::fromStdString(logItem->functionName);
            break;
        default:
            break;
        }
    }

    QApplication::clipboard()->setText(textToCopy);
}

void LogDockWidget::copySingleRow(const int row)
{
    const kEvent* logItem = visibleEventAt(row);
    if (logItem == nullptr)
    {
        return;
    }

    // 行复制按当前可见列输出，避免隐藏列仍被复制。
    QApplication::clipboard()->setText(buildVisibleRowText(*logItem));
}

void LogDockWidget::copySelectedRows()
{
    const std::vector<int> selectedRowIndexes = collectSelectedRowIndexes();
    if (selectedRowIndexes.empty())
    {
        return;
    }

    QStringList lines;
    lines.reserve(static_cast<int>(selectedRowIndexes.size()));

    // selectedRowIndexes 已按界面行号升序排列，这里直接按视觉顺序输出。
    for (const int row : selectedRowIndexes)
    {
        const kEvent* logItem = visibleEventAt(row);
        if (logItem == nullptr)
        {
            continue;
        }

        // 每一行仍复用 buildVisibleRowText，保证隐藏详细列时复制结果也不包含隐藏列。
        lines.push_back(buildVisibleRowText(*logItem));
    }

    if (!lines.isEmpty())
    {
        QApplication::clipboard()->setText(lines.join("\n"));
    }
}

void LogDockWidget::copyVisibleRows()
{
    const std::vector<kEvent>& currentVisibleEvents = visibleEvents();
    QStringList lines;
    lines.reserve(static_cast<int>(currentVisibleEvents.size()));

    // 遍历当前可见事件列表，保证与屏幕展示一致（含追踪/筛选状态）。
    for (const kEvent& logItem : currentVisibleEvents)
    {
        lines.push_back(buildVisibleRowText(logItem));
    }

    QApplication::clipboard()->setText(lines.join("\n"));
}

std::vector<int> LogDockWidget::collectSelectedRowIndexes() const
{
    std::vector<int> selectedRows;
    if (m_logTable == nullptr || m_logTable->selectionModel() == nullptr)
    {
        return selectedRows;
    }

    // selectedRows() 在 SelectRows 模式下只返回每行一个索引，比 selectedIndexes() 少遍历列数。
    // 若未来改成单元格选择导致 selectedRows() 为空，再回退到 selectedIndexes() 兼容旧逻辑。
    const QModelIndexList selectedRowIndexes = m_logTable->selectionModel()->selectedRows();
    const QModelIndexList selectedIndexes = selectedRowIndexes.isEmpty()
        ? m_logTable->selectionModel()->selectedIndexes()
        : selectedRowIndexes;
    selectedRows.reserve(static_cast<std::size_t>(selectedIndexes.size()));

    for (const QModelIndex& selectedIndex : selectedIndexes)
    {
        const int row = selectedIndex.row();
        if (visibleEventAt(row) != nullptr)
        {
            selectedRows.push_back(row);
        }
    }

    std::sort(selectedRows.begin(), selectedRows.end());
    selectedRows.erase(std::unique(selectedRows.begin(), selectedRows.end()), selectedRows.end());
    return selectedRows;
}

const std::vector<kEvent>& LogDockWidget::visibleEvents() const
{
    // emptyEvents 是模型未创建时的安全只读返回值。
    // 它避免每个调用点都做空指针分支，同时不产生额外临时 vector。
    static const std::vector<kEvent> emptyEvents;
    if (m_logModel == nullptr)
    {
        return emptyEvents;
    }

    return m_logModel->rows();
}

const kEvent* LogDockWidget::visibleEventAt(const int row) const
{
    if (m_logModel == nullptr)
    {
        return nullptr;
    }

    return m_logModel->rowAt(row);
}

QString LogDockWidget::buildVisibleRowText(const kEvent& logItem) const
{
    QStringList visibleFieldList;
    visibleFieldList.reserve(TotalColumns);

    // 始终输出基础三列；详细信息开启时再追加文件/函数列。
    visibleFieldList.push_back(getLevelText(logItem.level));
    visibleFieldList.push_back(QString::fromStdString(FormatTimeToString(logItem.timestamp)));
    visibleFieldList.push_back(QString::fromStdString(logItem.content));

    // detailVisible 用途：记录当前是否应输出详细列文本。
    const bool detailVisible = (m_detailCheck != nullptr) && m_detailCheck->isChecked();
    if (detailVisible)
    {
        visibleFieldList.push_back(QString::fromStdString(logItem.fileLocation));
        visibleFieldList.push_back(QString::fromStdString(logItem.functionName));
    }

    return visibleFieldList.join("\t");
}

void LogDockWidget::startTrackingByRow(const int row)
{
    const kEvent* logItem = visibleEventAt(row);
    if (logItem == nullptr)
    {
        return;
    }

    // 读取目标行 GUID 并进入追踪状态。
    m_trackingGuid = logItem->guid;
    m_isTracking = true;
    refreshTableFromManager(true);
}

void LogDockWidget::cancelTracking()
{
    // 退出追踪后回到“仅等级筛选”的常规视图。
    m_isTracking = false;
    m_trackingGuid = GUID{};
    refreshTableFromManager(true);
}

void LogDockWidget::exportAllLogs()
{
    QString outputPath = chooseExportPath();
    if (outputPath.isEmpty())
    {
        return;
    }

    // 统一保证后缀为 .txt。
    if (!outputPath.endsWith(".txt", Qt::CaseInsensitive))
    {
        outputPath += ".txt";
    }

    // 使用 UTF-8 字符串传给 Save，兼容中文路径。
    const bool saveOk = KswordARKEventEntry.Save(outputPath.toUtf8().toStdString());
    if (!saveOk)
    {
        QMessageBox::critical(this, "导出失败", "日志文件写入失败，请检查路径和权限。");
        return;
    }

    QMessageBox::information(this, "导出成功", "日志导出完成。");
}

QString LogDockWidget::chooseExportPath()
{
#ifdef _WIN32
    // Windows：优先调用原生 shell 保存对话框。
    wchar_t fileBuffer[MAX_PATH] = L"KswordARK_Log.txt";
    OPENFILENAMEW saveDialog{};
    saveDialog.lStructSize = sizeof(OPENFILENAMEW);
    saveDialog.hwndOwner = reinterpret_cast<HWND>(this->winId());
    saveDialog.lpstrFilter = L"Text Files (*.txt)\0*.txt\0All Files (*.*)\0*.*\0";
    saveDialog.lpstrFile = fileBuffer;
    saveDialog.nMaxFile = MAX_PATH;
    saveDialog.lpstrDefExt = L"txt";
    saveDialog.Flags = OFN_PATHMUSTEXIST | OFN_OVERWRITEPROMPT;

    if (::GetSaveFileNameW(&saveDialog) != FALSE)
    {
        return QString::fromWCharArray(fileBuffer).trimmed();
    }

    // 只有在 CommDlgExtendedError != 0 时认为对话框打开失败（而非用户取消）。
    const DWORD shellErrorCode = ::CommDlgExtendedError();
    if (shellErrorCode != 0)
    {
        bool inputOk = false;
        const QString manualPath = QInputDialog::getText(
            this,
            "Shell 打开失败",
            "检测到原生保存对话框调用失败，请手动输入导出路径：",
            QLineEdit::Normal,
            "KswordARK_Log.txt",
            &inputOk).trimmed();

        if (inputOk)
        {
            return manualPath;
        }
    }
    return QString();
#else
    // 非 Windows 平台：使用 Qt 原生接口。
    bool inputOk = false;
    const QString manualPath = QInputDialog::getText(
        this,
        "导出日志",
        "请输入导出路径：",
        QLineEdit::Normal,
        "KswordARK_Log.txt",
        &inputOk).trimmed();
    if (inputOk)
    {
        return manualPath;
    }
    return QString();
#endif
}

void LogDockWidget::clearAllLogsWithDoubleConfirm()
{
    // 第一次确认：常规确认。
    const QMessageBox::StandardButton firstConfirm = QMessageBox::question(
        this,
        "确认清空",
        "确定要清空日志列表吗？",
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    if (firstConfirm != QMessageBox::Yes)
    {
        return;
    }

    // 第二次确认：不可恢复提示。
    const QMessageBox::StandardButton secondConfirm = QMessageBox::warning(
        this,
        "二次确认",
        "该操作不可恢复，是否继续清空全部日志？",
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    if (secondConfirm != QMessageBox::Yes)
    {
        return;
    }

    // 真正执行清空，并退出追踪状态避免空追踪锁死视图。
    KswordARKEventEntry.clear();
    m_isTracking = false;
    m_trackingGuid = GUID{};
    refreshTableFromManager(true);
}
