#include "KernelCallbackMonitorWidget.h"

#include "../Internationalization/LanguageManager.h"
#include "../UI/TableInteractionSupport.h"
#include "../UI/VisibleTableWidget.h"
#include "../theme.h"

#include <QAbstractTableModel>
#include <QCheckBox>
#include <QComboBox>
#include <QDateTime>
#include <QFileDialog>
#include <QFileInfo>
#include <QGridLayout>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QIcon>
#include <QItemSelectionModel>
#include <QLabel>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QRegularExpression>
#include <QSaveFile>
#include <QScrollBar>
#include <QSortFilterProxyModel>
#include <QSpinBox>
#include <QSplitter>
#include <QTextStream>
#include <QStringConverter>
#include <QTimer>
#include <QTimeZone>
#include <QVariant>
#include <QVBoxLayout>

#include <algorithm>
#include <chrono>
#include <limits>

namespace
{
    enum CallbackColumn
    {
        CallbackColumnSequence = 0,
        CallbackColumnTime,
        CallbackColumnCategory,
        CallbackColumnOperation,
        CallbackColumnProcess,
        CallbackColumnPidTid,
        CallbackColumnTarget,
        CallbackColumnResult,
        CallbackColumnPath,
        CallbackColumnSummary,
        CallbackColumnCount
    };

    QString callbackCategoryText(const std::uint32_t category)
    {
        switch (category)
        {
        case KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_PROCESS:
            return QStringLiteral("进程");
        case KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_THREAD:
            return QStringLiteral("线程");
        case KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_IMAGE:
            return QStringLiteral("镜像");
        case KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_REGISTRY:
            return QStringLiteral("注册表");
        case KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_OBJECT:
            return QStringLiteral("对象");
        case KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_MINIFILTER:
            return QStringLiteral("文件");
        default:
            return QStringLiteral("未知");
        }
    }

    QString callbackOperationText(const ksword::ark::CallbackMonitorEventRow& row)
    {
        if (row.category == KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_PROCESS)
        {
            return row.operation == KSWORD_ARK_CALLBACK_MONITOR_PROCESS_OP_EXIT
                ? QStringLiteral("退出")
                : QStringLiteral("创建");
        }
        if (row.category == KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_THREAD)
        {
            return row.operation == KSWORD_ARK_THREAD_OP_EXIT
                ? QStringLiteral("退出")
                : QStringLiteral("创建");
        }
        if (row.category == KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_IMAGE)
        {
            return QStringLiteral("加载");
        }
        if (row.category == KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_REGISTRY)
        {
            switch (row.operation)
            {
            case KSWORD_ARK_REG_OP_CREATE_KEY: return QStringLiteral("创建键");
            case KSWORD_ARK_REG_OP_OPEN_KEY: return QStringLiteral("打开键");
            case KSWORD_ARK_REG_OP_DELETE_KEY: return QStringLiteral("删除键");
            case KSWORD_ARK_REG_OP_SET_VALUE: return QStringLiteral("设置值");
            case KSWORD_ARK_REG_OP_DELETE_VALUE: return QStringLiteral("删除值");
            case KSWORD_ARK_REG_OP_RENAME_KEY: return QStringLiteral("重命名键");
            case KSWORD_ARK_REG_OP_SET_INFO: return QStringLiteral("设置键信息");
            case KSWORD_ARK_REG_OP_QUERY_VALUE: return QStringLiteral("查询值");
            default: break;
            }
        }
        if (row.category == KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_OBJECT)
        {
            const QString objectText = (row.operation & KSWORD_ARK_OBJECT_OP_TYPE_THREAD) != 0UL
                ? QStringLiteral("线程句柄")
                : QStringLiteral("进程句柄");
            const QString actionText = (row.operation & KSWORD_ARK_OBJECT_OP_HANDLE_DUPLICATE) != 0UL
                ? QStringLiteral("复制")
                : QStringLiteral("创建");
            return QStringLiteral("%1%2").arg(actionText, objectText);
        }
        if (row.category == KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_MINIFILTER)
        {
            switch (row.operation)
            {
            case KSWORD_ARK_FILE_MONITOR_OPERATION_CREATE: return QStringLiteral("创建/打开");
            case KSWORD_ARK_FILE_MONITOR_OPERATION_READ: return QStringLiteral("读取");
            case KSWORD_ARK_FILE_MONITOR_OPERATION_WRITE: return QStringLiteral("写入");
            case KSWORD_ARK_FILE_MONITOR_OPERATION_SETINFO: return QStringLiteral("设置信息");
            case KSWORD_ARK_FILE_MONITOR_OPERATION_RENAME: return QStringLiteral("重命名");
            case KSWORD_ARK_FILE_MONITOR_OPERATION_DELETE: return QStringLiteral("删除");
            case KSWORD_ARK_FILE_MONITOR_OPERATION_CLEANUP: return QStringLiteral("清理");
            case KSWORD_ARK_FILE_MONITOR_OPERATION_CLOSE: return QStringLiteral("关闭");
            case KSWORD_ARK_FILE_MONITOR_OPERATION_FSCTL: return QStringLiteral("FSCTL");
            default: break;
            }
        }
        return QStringLiteral("0x%1").arg(row.operation, 8, 16, QLatin1Char('0')).toUpper();
    }

    QString callbackTimeText(const std::int64_t timeUtc100ns)
    {
        constexpr std::int64_t windowsToUnix100ns = 116444736000000000LL;
        const std::int64_t unixMilliseconds = (timeUtc100ns - windowsToUnix100ns) / 10000LL;
        return QDateTime::fromMSecsSinceEpoch(unixMilliseconds, QTimeZone::UTC)
            .toLocalTime()
            .toString(QStringLiteral("yyyy-MM-dd HH:mm:ss.zzz"));
    }

    QString callbackProcessText(const ksword::ark::CallbackMonitorEventRow& row)
    {
        const QString fullText = QString::fromStdWString(row.processName);
        const QString fileName = QFileInfo(fullText).fileName();
        return fileName.isEmpty() ? fullText : fileName;
    }

    QString callbackPidTidText(const ksword::ark::CallbackMonitorEventRow& row)
    {
        return QStringLiteral("%1 / %2")
            .arg(row.originatingProcessId)
            .arg(row.originatingThreadId);
    }

    QString callbackTargetText(const ksword::ark::CallbackMonitorEventRow& row)
    {
        if (row.targetProcessId == 0U && row.targetThreadId == 0U)
        {
            return QStringLiteral("-");
        }
        return QStringLiteral("%1 / %2")
            .arg(row.targetProcessId)
            .arg(row.targetThreadId);
    }

    QString callbackResultText(const ksword::ark::CallbackMonitorEventRow& row)
    {
        if ((row.flags & KSWORD_ARK_CALLBACK_MONITOR_EVENT_FLAG_STATUS_PRESENT) == 0UL)
        {
            return QStringLiteral("-");
        }
        return QStringLiteral("0x%1")
            .arg(static_cast<quint32>(row.resultStatus), 8, 16, QLatin1Char('0'))
            .toUpper();
    }

    QString callbackSummaryText(const ksword::ark::CallbackMonitorEventRow& row)
    {
        if ((row.flags & KSWORD_ARK_CALLBACK_MONITOR_EVENT_FLAG_ACCESS_PRESENT) != 0UL)
        {
            return QStringLiteral("访问 0x%1 → 0x%2")
                .arg(row.originalAccess, 8, 16, QLatin1Char('0'))
                .arg(row.desiredAccess, 8, 16, QLatin1Char('0'))
                .toUpper();
        }
        if (row.category == KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_IMAGE)
        {
            return QStringLiteral("地址 0x%1，大小 0x%2")
                .arg(row.address, 0, 16)
                .arg(row.regionSize, 0, 16)
                .toUpper();
        }
        if (row.category == KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_MINIFILTER)
        {
            return QStringLiteral("Major/Minor 0x%1/0x%2")
                .arg((row.detailCode >> 8) & 0xFFU, 2, 16, QLatin1Char('0'))
                .arg(row.detailCode & 0xFFU, 2, 16, QLatin1Char('0'))
                .toUpper();
        }
        return QStringLiteral("父 PID %1，Session %2")
            .arg(row.parentProcessId)
            .arg(row.sessionId);
    }

    QPushButton* createCallbackIconButton(
        QWidget* parent,
        const QString& iconPath,
        const QString& toolTip)
    {
        QPushButton* button = new QPushButton(parent);
        button->setIcon(QIcon(iconPath));
        button->setToolTip(toolTip);
        KswordTheme::ApplyCompactIconButtonMetrics(button);
        return button;
    }
}

class KernelCallbackEventModel final : public QAbstractTableModel
{
public:
    explicit KernelCallbackEventModel(QObject* parent = nullptr)
        : QAbstractTableModel(parent)
    {
    }

    int rowCount(const QModelIndex& parent = QModelIndex()) const override
    {
        return parent.isValid() ? 0 : static_cast<int>(m_rows.size());
    }

    int columnCount(const QModelIndex& parent = QModelIndex()) const override
    {
        return parent.isValid() ? 0 : CallbackColumnCount;
    }

    QVariant headerData(
        const int section,
        const Qt::Orientation orientation,
        const int role) const override
    {
        if (orientation != Qt::Horizontal || role != Qt::DisplayRole)
        {
            return {};
        }
        static const QStringList headers{
            QStringLiteral("序号"),
            QStringLiteral("时间"),
            QStringLiteral("类别"),
            QStringLiteral("操作"),
            QStringLiteral("进程"),
            QStringLiteral("PID / TID"),
            QStringLiteral("目标 PID / TID"),
            QStringLiteral("结果"),
            QStringLiteral("路径"),
            QStringLiteral("摘要")
        };
        return section >= 0 && section < headers.size()
            ? ks::i18n::sourceText(headers.at(section))
            : QVariant();
    }

    QVariant data(const QModelIndex& index, const int role) const override
    {
        const ksword::ark::CallbackMonitorEventRow* row = rowAt(index.row());
        if (row == nullptr || index.column() < 0 || index.column() >= CallbackColumnCount)
        {
            return {};
        }
        if (role == Qt::UserRole)
        {
            switch (index.column())
            {
            case CallbackColumnSequence: return QVariant::fromValue<qulonglong>(row->sequence);
            case CallbackColumnTime: return QVariant::fromValue<qlonglong>(row->timeUtc100ns);
            case CallbackColumnCategory: return row->category;
            case CallbackColumnOperation: return row->operation;
            case CallbackColumnPidTid: return row->originatingProcessId;
            case CallbackColumnTarget: return row->targetProcessId;
            case CallbackColumnResult: return static_cast<qlonglong>(row->resultStatus);
            default: break;
            }
        }
        if (role != Qt::DisplayRole && role != Qt::ToolTipRole)
        {
            return {};
        }

        switch (index.column())
        {
        case CallbackColumnSequence: return QString::number(row->sequence);
        case CallbackColumnTime: return callbackTimeText(row->timeUtc100ns);
        case CallbackColumnCategory: return ks::i18n::sourceText(callbackCategoryText(row->category));
        case CallbackColumnOperation: return ks::i18n::sourceText(callbackOperationText(*row));
        case CallbackColumnProcess: return callbackProcessText(*row);
        case CallbackColumnPidTid: return callbackPidTidText(*row);
        case CallbackColumnTarget: return callbackTargetText(*row);
        case CallbackColumnResult: return callbackResultText(*row);
        case CallbackColumnPath: return QString::fromStdWString(row->path);
        case CallbackColumnSummary: return ks::i18n::sourceText(callbackSummaryText(*row));
        default: return {};
        }
    }

    const ksword::ark::CallbackMonitorEventRow* rowAt(const int row) const
    {
        if (row < 0 || row >= static_cast<int>(m_rows.size()))
        {
            return nullptr;
        }
        return &m_rows[static_cast<std::size_t>(row)];
    }

    void appendRows(
        std::vector<ksword::ark::CallbackMonitorEventRow> rows,
        const int maximumRows)
    {
        if (rows.empty())
        {
            return;
        }
        const int firstRow = static_cast<int>(m_rows.size());
        beginInsertRows(QModelIndex(), firstRow, firstRow + static_cast<int>(rows.size()) - 1);
        for (auto& row : rows)
        {
            m_rows.push_back(std::move(row));
        }
        endInsertRows();
        trimRows(maximumRows);
    }

    void trimRows(const int maximumRows)
    {
        const int removeCount = std::max(0, static_cast<int>(m_rows.size()) - maximumRows);
        if (removeCount == 0)
        {
            return;
        }
        beginRemoveRows(QModelIndex(), 0, removeCount - 1);
        m_rows.erase(m_rows.begin(), m_rows.begin() + removeCount);
        endRemoveRows();
    }

    void clearRows()
    {
        if (m_rows.empty())
        {
            return;
        }
        beginResetModel();
        m_rows.clear();
        endResetModel();
    }

private:
    std::deque<ksword::ark::CallbackMonitorEventRow> m_rows;
};

class KernelCallbackFilterModel final : public QSortFilterProxyModel
{
public:
    explicit KernelCallbackFilterModel(QObject* parent = nullptr)
        : QSortFilterProxyModel(parent)
    {
        setDynamicSortFilter(true);
        setSortRole(Qt::UserRole);
    }

    void setFilters(
        const std::uint32_t category,
        const QString& operation,
        const QString& pid,
        const QString& process,
        const QString& path,
        const QString& result,
        const bool regex)
    {
        const QString normalizedOperation = operation.trimmed();
        const QString normalizedPid = pid.trimmed();
        const QString normalizedProcess = process.trimmed();
        const QString normalizedPath = path.trimmed();
        const QString normalizedResult = result.trimmed();
        if (m_category == category &&
            m_operation == normalizedOperation &&
            m_pid == normalizedPid &&
            m_process == normalizedProcess &&
            m_path == normalizedPath &&
            m_result == normalizedResult &&
            m_regex == regex)
        {
            return;
        }

        m_category = category;
        m_operation = normalizedOperation;
        m_pid = normalizedPid;
        m_process = normalizedProcess;
        m_path = normalizedPath;
        m_result = normalizedResult;
        m_regex = regex;
        m_invalidRegex = false;
        if (m_regex)
        {
            m_operationRegex = QRegularExpression(m_operation, QRegularExpression::CaseInsensitiveOption);
            m_pidRegex = QRegularExpression(m_pid, QRegularExpression::CaseInsensitiveOption);
            m_processRegex = QRegularExpression(m_process, QRegularExpression::CaseInsensitiveOption);
            m_pathRegex = QRegularExpression(m_path, QRegularExpression::CaseInsensitiveOption);
            m_resultRegex = QRegularExpression(m_result, QRegularExpression::CaseInsensitiveOption);
            m_invalidRegex =
                (!m_operation.isEmpty() && !m_operationRegex.isValid()) ||
                (!m_pid.isEmpty() && !m_pidRegex.isValid()) ||
                (!m_process.isEmpty() && !m_processRegex.isValid()) ||
                (!m_path.isEmpty() && !m_pathRegex.isValid()) ||
                (!m_result.isEmpty() && !m_resultRegex.isValid());
        }
        invalidateRowsFilter();
    }

    bool invalidRegex() const
    {
        return m_invalidRegex;
    }

protected:
    bool filterAcceptsRow(const int sourceRow, const QModelIndex& sourceParent) const override
    {
        Q_UNUSED(sourceParent);
        const auto* model = static_cast<const KernelCallbackEventModel*>(sourceModel());
        const auto* row = model != nullptr ? model->rowAt(sourceRow) : nullptr;
        if (row == nullptr || m_invalidRegex)
        {
            return false;
        }
        if (m_category != 0U && row->category != m_category)
        {
            return false;
        }
        const QString pidText = QStringLiteral("%1 %2 %3 %4 %5")
            .arg(row->originatingProcessId)
            .arg(row->originatingThreadId)
            .arg(row->targetProcessId)
            .arg(row->targetThreadId)
            .arg(row->parentProcessId);
        const QString processText = QStringLiteral("%1 %2")
            .arg(QString::fromStdWString(row->processName), callbackProcessText(*row));
        const QString operationSourceText = callbackOperationText(*row);
        const QString operationDisplayText = ks::i18n::sourceText(operationSourceText);
        const QString operationSearchText = operationDisplayText == operationSourceText
            ? operationSourceText
            : QStringLiteral("%1 %2").arg(operationSourceText, operationDisplayText);
        return matches(m_operation, operationSearchText, m_operationRegex) &&
            matches(m_pid, pidText, m_pidRegex) &&
            matches(m_process, processText, m_processRegex) &&
            matches(m_path, QString::fromStdWString(row->path), m_pathRegex) &&
            matches(m_result, callbackResultText(*row), m_resultRegex);
    }

private:
    bool matches(
        const QString& pattern,
        const QString& value,
        const QRegularExpression& expression) const
    {
        if (pattern.isEmpty())
        {
            return true;
        }
        if (!m_regex)
        {
            return value.contains(pattern, Qt::CaseInsensitive);
        }
        return expression.match(value).hasMatch();
    }

    std::uint32_t m_category = 0;
    QString m_operation;
    QString m_pid;
    QString m_process;
    QString m_path;
    QString m_result;
    QRegularExpression m_operationRegex;
    QRegularExpression m_pidRegex;
    QRegularExpression m_processRegex;
    QRegularExpression m_pathRegex;
    QRegularExpression m_resultRegex;
    bool m_regex = false;
    bool m_invalidRegex = false;
};

KernelCallbackMonitorWidget::KernelCallbackMonitorWidget(QWidget* parent)
    : QWidget(parent)
{
    initializeUi();
    initializeConnections();
    updateActionState();
    updateStatusLabel();
}

KernelCallbackMonitorWidget::~KernelCallbackMonitorWidget()
{
    if (m_uiTimer != nullptr)
    {
        m_uiTimer->stop();
    }
    stopCapture(true);
}

void KernelCallbackMonitorWidget::initializeUi()
{
    m_rootLayout = new QVBoxLayout(this);
    m_rootLayout->setContentsMargins(6, 6, 6, 6);
    m_rootLayout->setSpacing(6);

    QWidget* controlPanel = new QWidget(this);
    QGridLayout* controlLayout = new QGridLayout(controlPanel);
    controlLayout->setContentsMargins(6, 6, 6, 6);
    controlLayout->setHorizontalSpacing(8);
    controlLayout->setVerticalSpacing(6);
    controlLayout->addWidget(new QLabel(QStringLiteral("采集类别"), controlPanel), 0, 0);
    m_processCheck = new QCheckBox(QStringLiteral("进程"), controlPanel);
    m_threadCheck = new QCheckBox(QStringLiteral("线程"), controlPanel);
    m_imageCheck = new QCheckBox(QStringLiteral("镜像"), controlPanel);
    m_registryCheck = new QCheckBox(QStringLiteral("注册表"), controlPanel);
    m_objectCheck = new QCheckBox(QStringLiteral("对象"), controlPanel);
    m_fileCheck = new QCheckBox(QStringLiteral("文件（高频）"), controlPanel);
    m_processCheck->setChecked(true);
    m_threadCheck->setChecked(true);
    m_imageCheck->setChecked(true);
    m_registryCheck->setChecked(true);
    m_objectCheck->setChecked(true);
    m_fileCheck->setChecked(false);
    controlLayout->addWidget(m_processCheck, 0, 1);
    controlLayout->addWidget(m_threadCheck, 0, 2);
    controlLayout->addWidget(m_imageCheck, 0, 3);
    controlLayout->addWidget(m_registryCheck, 0, 4);
    controlLayout->addWidget(m_objectCheck, 0, 5);
    controlLayout->addWidget(m_fileCheck, 0, 6);

    controlLayout->addWidget(new QLabel(QStringLiteral("最大行数"), controlPanel), 1, 0);
    m_maxRowsSpin = new QSpinBox(controlPanel);
    m_maxRowsSpin->setRange(1000, 100000);
    m_maxRowsSpin->setSingleStep(1000);
    m_maxRowsSpin->setValue(20000);
    controlLayout->addWidget(m_maxRowsSpin, 1, 1, 1, 2);
    m_startButton = createCallbackIconButton(
        controlPanel,
        QStringLiteral(":/Icon/process_start.svg"),
        QStringLiteral("开始内核回调监控"));
    m_stopButton = createCallbackIconButton(
        controlPanel,
        QStringLiteral(":/Icon/process_terminate.svg"),
        QStringLiteral("停止内核回调监控"));
    m_pauseButton = createCallbackIconButton(
        controlPanel,
        QStringLiteral(":/Icon/process_pause.svg"),
        QStringLiteral("暂停事件入表，后台继续读取"));
    m_clearButton = createCallbackIconButton(
        controlPanel,
        QStringLiteral(":/Icon/log_clear.svg"),
        QStringLiteral("清空当前页面并跳过已有事件"));
    m_exportButton = createCallbackIconButton(
        controlPanel,
        QStringLiteral(":/Icon/log_export.svg"),
        QStringLiteral("导出当前可见事件为 CSV"));
    QHBoxLayout* buttonLayout = new QHBoxLayout();
    buttonLayout->setContentsMargins(0, 0, 0, 0);
    buttonLayout->setSpacing(6);
    buttonLayout->addWidget(m_startButton);
    buttonLayout->addWidget(m_stopButton);
    buttonLayout->addWidget(m_pauseButton);
    buttonLayout->addWidget(m_clearButton);
    buttonLayout->addWidget(m_exportButton);
    buttonLayout->addStretch(1);
    controlLayout->addLayout(buttonLayout, 1, 3, 1, 4);
    m_statusLabel = new QLabel(QStringLiteral("● 空闲"), controlPanel);
    controlLayout->addWidget(m_statusLabel, 2, 0, 1, 7);
    m_rootLayout->addWidget(controlPanel, 0);

    QWidget* filterPanel = new QWidget(this);
    QGridLayout* filterLayout = new QGridLayout(filterPanel);
    filterLayout->setContentsMargins(6, 6, 6, 6);
    filterLayout->setHorizontalSpacing(6);
    filterLayout->setVerticalSpacing(6);
    filterLayout->addWidget(new QLabel(QStringLiteral("类别"), filterPanel), 0, 0);
    m_categoryFilterCombo = new QComboBox(filterPanel);
    m_categoryFilterCombo->addItem(QStringLiteral("全部类别"), QVariant::fromValue<qulonglong>(0U));
    m_categoryFilterCombo->addItem(QStringLiteral("进程"), QVariant::fromValue<qulonglong>(KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_PROCESS));
    m_categoryFilterCombo->addItem(QStringLiteral("线程"), QVariant::fromValue<qulonglong>(KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_THREAD));
    m_categoryFilterCombo->addItem(QStringLiteral("镜像"), QVariant::fromValue<qulonglong>(KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_IMAGE));
    m_categoryFilterCombo->addItem(QStringLiteral("注册表"), QVariant::fromValue<qulonglong>(KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_REGISTRY));
    m_categoryFilterCombo->addItem(QStringLiteral("对象"), QVariant::fromValue<qulonglong>(KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_OBJECT));
    m_categoryFilterCombo->addItem(QStringLiteral("文件"), QVariant::fromValue<qulonglong>(KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_MINIFILTER));
    filterLayout->addWidget(m_categoryFilterCombo, 0, 1);
    filterLayout->addWidget(new QLabel(QStringLiteral("操作"), filterPanel), 0, 2);
    m_operationFilterEdit = new QLineEdit(filterPanel);
    m_operationFilterEdit->setPlaceholderText(QStringLiteral("创建、退出、写入…"));
    filterLayout->addWidget(m_operationFilterEdit, 0, 3);
    filterLayout->addWidget(new QLabel(QStringLiteral("PID"), filterPanel), 0, 4);
    m_pidFilterEdit = new QLineEdit(filterPanel);
    m_pidFilterEdit->setPlaceholderText(QStringLiteral("来源、目标或父 PID"));
    filterLayout->addWidget(m_pidFilterEdit, 0, 5);

    filterLayout->addWidget(new QLabel(QStringLiteral("进程"), filterPanel), 1, 0);
    m_processFilterEdit = new QLineEdit(filterPanel);
    m_processFilterEdit->setPlaceholderText(QStringLiteral("进程名或映像路径"));
    filterLayout->addWidget(m_processFilterEdit, 1, 1);
    filterLayout->addWidget(new QLabel(QStringLiteral("路径"), filterPanel), 1, 2);
    m_pathFilterEdit = new QLineEdit(filterPanel);
    m_pathFilterEdit->setPlaceholderText(QStringLiteral("映像、注册表或文件路径"));
    filterLayout->addWidget(m_pathFilterEdit, 1, 3);
    filterLayout->addWidget(new QLabel(QStringLiteral("结果"), filterPanel), 1, 4);
    m_resultFilterEdit = new QLineEdit(filterPanel);
    m_resultFilterEdit->setPlaceholderText(QStringLiteral("NTSTATUS 十六进制"));
    filterLayout->addWidget(m_resultFilterEdit, 1, 5);
    m_regexCheck = new QCheckBox(QStringLiteral("正则"), filterPanel);
    m_keepBottomCheck = new QCheckBox(QStringLiteral("保持贴底"), filterPanel);
    m_keepBottomCheck->setChecked(true);
    m_filterStatusLabel = new QLabel(QStringLiteral("筛选结果：0 / 0"), filterPanel);
    filterLayout->addWidget(m_regexCheck, 2, 0);
    filterLayout->addWidget(m_keepBottomCheck, 2, 1);
    filterLayout->addWidget(m_filterStatusLabel, 2, 2, 1, 4);
    m_rootLayout->addWidget(filterPanel, 0);

    m_eventModel = new KernelCallbackEventModel(this);
    m_filterModel = new KernelCallbackFilterModel(this);
    m_filterModel->setSourceModel(m_eventModel);
    m_eventTable = new ks::ui::TableActionTableView(this);
    m_eventTable->setModel(m_filterModel);
    m_eventTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_eventTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_eventTable->setSelectionMode(QAbstractItemView::ExtendedSelection);
    m_eventTable->setAlternatingRowColors(true);
    m_eventTable->setSortingEnabled(true);
    m_eventTable->sortByColumn(CallbackColumnSequence, Qt::AscendingOrder);
    m_eventTable->verticalHeader()->setVisible(false);
    m_eventTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
    m_eventTable->setColumnWidth(CallbackColumnSequence, 90);
    m_eventTable->setColumnWidth(CallbackColumnTime, 170);
    m_eventTable->setColumnWidth(CallbackColumnCategory, 78);
    m_eventTable->setColumnWidth(CallbackColumnOperation, 120);
    m_eventTable->setColumnWidth(CallbackColumnProcess, 160);
    m_eventTable->setColumnWidth(CallbackColumnPidTid, 110);
    m_eventTable->setColumnWidth(CallbackColumnTarget, 120);
    m_eventTable->setColumnWidth(CallbackColumnResult, 100);
    m_eventTable->setColumnWidth(CallbackColumnPath, 360);
    m_eventTable->setColumnWidth(CallbackColumnSummary, 260);

    m_detailEdit = new QPlainTextEdit(this);
    m_detailEdit->setReadOnly(true);
    m_detailEdit->setPlaceholderText(QStringLiteral("选择事件后查看完整字段详情"));
    QSplitter* resultSplitter = new QSplitter(Qt::Vertical, this);
    resultSplitter->addWidget(m_eventTable);
    resultSplitter->addWidget(m_detailEdit);
    resultSplitter->setStretchFactor(0, 4);
    resultSplitter->setStretchFactor(1, 1);
    resultSplitter->setSizes(QList<int>{ 620, 150 });
    m_rootLayout->addWidget(resultSplitter, 1);

    m_uiTimer = new QTimer(this);
    m_uiTimer->setInterval(100);
    m_uiTimer->start();
}

void KernelCallbackMonitorWidget::initializeConnections()
{
    connect(m_startButton, &QPushButton::clicked, this, [this]() { startCapture(); });
    connect(m_stopButton, &QPushButton::clicked, this, [this]() { stopCapture(false); });
    connect(m_pauseButton, &QPushButton::clicked, this, [this]() { setPaused(!m_paused.load()); });
    connect(m_clearButton, &QPushButton::clicked, this, [this]() { clearLocalEvents(); });
    connect(m_exportButton, &QPushButton::clicked, this, [this]() { exportVisibleRows(); });
    connect(m_uiTimer, &QTimer::timeout, this, [this]() { flushPendingEvents(); });
    connect(m_maxRowsSpin, QOverload<int>::of(&QSpinBox::valueChanged), this, [this](const int value) {
        m_pendingLimit.store(value);
        m_eventModel->trimRows(value);
        updateStatusLabel();
    });

    const auto filterChanged = [this]() { applyFilters(); };
    connect(m_categoryFilterCombo, QOverload<int>::of(&QComboBox::currentIndexChanged), this, filterChanged);
    connect(m_operationFilterEdit, &QLineEdit::textChanged, this, filterChanged);
    connect(m_pidFilterEdit, &QLineEdit::textChanged, this, filterChanged);
    connect(m_processFilterEdit, &QLineEdit::textChanged, this, filterChanged);
    connect(m_pathFilterEdit, &QLineEdit::textChanged, this, filterChanged);
    connect(m_resultFilterEdit, &QLineEdit::textChanged, this, filterChanged);
    connect(m_regexCheck, &QCheckBox::toggled, this, filterChanged);
    connect(m_eventTable->selectionModel(), &QItemSelectionModel::selectionChanged, this, [this]() {
        updateDetailPanel();
    });
}

unsigned long KernelCallbackMonitorWidget::selectedCategoryMask() const
{
    unsigned long mask = 0UL;
    if (m_processCheck->isChecked()) mask |= KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_PROCESS;
    if (m_threadCheck->isChecked()) mask |= KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_THREAD;
    if (m_imageCheck->isChecked()) mask |= KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_IMAGE;
    if (m_registryCheck->isChecked()) mask |= KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_REGISTRY;
    if (m_objectCheck->isChecked()) mask |= KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_OBJECT;
    if (m_fileCheck->isChecked()) mask |= KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_MINIFILTER;
    return mask;
}

void KernelCallbackMonitorWidget::startCapture()
{
    const unsigned long mask = selectedCategoryMask();
    if (mask == 0UL)
    {
        m_lastDisplayedError = QStringLiteral("请至少选择一个采集类别");
        updateStatusLabel();
        return;
    }
    if (m_captureRunning.load())
    {
        setPaused(false);
        return;
    }
    if (m_worker.joinable())
    {
        m_worker.join();
    }

    ksword::ark::DriverClient client;
    if (m_driverCaptureActive.load())
    {
        const ksword::ark::CallbackMonitorStatusResult cleanupStatus = client.controlCallbackMonitor(
            KSWORD_ARK_CALLBACK_MONITOR_ACTION_STOP,
            0UL);
        if (!cleanupStatus.io.ok)
        {
            m_lastDisplayedError = QString::fromStdString(cleanupStatus.io.message);
            updateActionState();
            updateStatusLabel();
            return;
        }
        m_driverCaptureActive.store(false);
        m_runtimeFlags.store(cleanupStatus.runtimeFlags);
        m_activeCategoryMask.store(cleanupStatus.categoryMask);
    }
    const ksword::ark::CallbackMonitorStatusResult status = client.controlCallbackMonitor(
        KSWORD_ARK_CALLBACK_MONITOR_ACTION_START,
        mask);
    if (!status.io.ok)
    {
        m_lastDisplayedError = status.unsupported
            ? QStringLiteral("当前驱动不支持内核回调监控，请更新驱动")
            : QString::fromStdString(status.io.message);
        updateStatusLabel();
        return;
    }

    m_workerStop.store(false);
    m_paused.store(false);
    m_cursorResetRequested.store(false);
    m_readerGeneration.fetch_add(1ULL);
    m_latestSequence.store(status.latestSequence);
    m_cursorResetValue.store(status.latestSequence);
    m_cursorResetRequested.store(true);
    m_r0DroppedCount.store(status.droppedCount);
    m_cursorLostCount.store(0ULL);
    m_r3DroppedCount.store(0ULL);
    m_runtimeFlags.store(status.runtimeFlags);
    m_activeCategoryMask.store(status.categoryMask);
    m_ringCapacity.store(status.ringCapacity);
    m_lastDisplayedError.clear();
    {
        std::lock_guard<std::mutex> lock(m_pendingMutex);
        m_pendingEvents.clear();
        m_workerError.clear();
        m_workerUnsupported = false;
    }
    m_eventModel->clearRows();
    m_driverCaptureActive.store(true);
    m_captureRunning.store(true);
    m_worker = std::thread(&KernelCallbackMonitorWidget::workerMain, this);
    updateActionState();
    updateStatusLabel();
}

void KernelCallbackMonitorWidget::stopCapture(const bool destroying)
{
    const bool wasRunning = m_captureRunning.exchange(false);
    m_workerStop.store(true);
    m_workerWake.notify_all();
    if (m_worker.joinable())
    {
        m_worker.join();
    }
    m_paused.store(false);
    if (wasRunning || m_driverCaptureActive.load())
    {
        ksword::ark::DriverClient client;
        const ksword::ark::CallbackMonitorStatusResult status = client.controlCallbackMonitor(
            KSWORD_ARK_CALLBACK_MONITOR_ACTION_STOP,
            0UL);
        if (!destroying && !status.io.ok)
        {
            m_lastDisplayedError = QString::fromStdString(status.io.message);
        }
        if (status.io.ok)
        {
            m_driverCaptureActive.store(false);
        }
        m_runtimeFlags.store(status.runtimeFlags);
        m_activeCategoryMask.store(status.categoryMask);
    }
    if (!destroying)
    {
        updateActionState();
        updateStatusLabel();
    }
}

void KernelCallbackMonitorWidget::setPaused(const bool paused)
{
    if (!m_captureRunning.load())
    {
        return;
    }
    m_paused.store(paused);
    updateActionState();
    updateStatusLabel();
}

void KernelCallbackMonitorWidget::clearLocalEvents()
{
    ksword::ark::DriverClient client;
    const auto status = client.queryCallbackMonitorStatus();
    const std::uint64_t latest = status.io.ok ? status.latestSequence : m_latestSequence.load();
    if (status.io.ok)
    {
        m_ringCapacity.store(status.ringCapacity);
    }
    m_readerGeneration.fetch_add(1ULL);
    m_cursorResetValue.store(latest);
    m_cursorResetRequested.store(true);
    {
        std::lock_guard<std::mutex> lock(m_pendingMutex);
        m_pendingEvents.clear();
    }
    m_eventModel->clearRows();
    m_cursorLostCount.store(0ULL);
    m_r3DroppedCount.store(0ULL);
    m_detailEdit->clear();
    applyFilters();
    updateStatusLabel();
    m_workerWake.notify_all();
}

void KernelCallbackMonitorWidget::workerMain()
{
    ksword::ark::DriverClient client;
    const auto stopDriverAfterFailure = [this, &client](ksword::ark::DriverHandle* const existingHandle) {
        const ksword::ark::CallbackMonitorStatusResult stopStatus = existingHandle != nullptr
            ? client.controlCallbackMonitor(
                *existingHandle,
                KSWORD_ARK_CALLBACK_MONITOR_ACTION_STOP,
                0UL)
            : client.controlCallbackMonitor(
                KSWORD_ARK_CALLBACK_MONITOR_ACTION_STOP,
                0UL);
        if (stopStatus.io.ok)
        {
            m_driverCaptureActive.store(false);
            m_runtimeFlags.store(stopStatus.runtimeFlags);
            m_activeCategoryMask.store(stopStatus.categoryMask);
        }
        m_captureRunning.store(false);
        m_paused.store(false);
        m_workerStop.store(true);
    };

    ksword::ark::DriverHandle handle = client.open();
    if (!handle.isValid())
    {
        recordWorkerFailure("open KswordARK control device failed", false);
        stopDriverAfterFailure(nullptr);
        return;
    }

    std::uint64_t cursor = m_cursorResetValue.load();
    while (!m_workerStop.load())
    {
        if (m_cursorResetRequested.exchange(false))
        {
            cursor = m_cursorResetValue.load();
        }
        const std::uint64_t generation = m_readerGeneration.load();
        ksword::ark::CallbackMonitorReadResult readResult = client.readCallbackMonitor(
            handle,
            cursor,
            KSWORD_ARK_CALLBACK_MONITOR_MAX_READ_RECORDS);
        if (!readResult.io.ok)
        {
            recordWorkerFailure(readResult.io.message, readResult.unsupported);
            stopDriverAfterFailure(&handle);
            break;
        }
        if (generation != m_readerGeneration.load())
        {
            continue;
        }

        cursor = readResult.nextSequence;
        m_latestSequence.store(readResult.latestSequence);
        m_r0DroppedCount.store(readResult.droppedCount);
        m_cursorLostCount.fetch_add(readResult.lostBeforeFirst);
        m_runtimeFlags.store(readResult.runtimeFlags);
        m_activeCategoryMask.store(readResult.categoryMask);
        m_ringCapacity.store(readResult.ringCapacity);
        if (!readResult.records.empty())
        {
            std::lock_guard<std::mutex> lock(m_pendingMutex);
            for (auto& record : readResult.records)
            {
                m_pendingEvents.push_back(std::move(record));
            }
            const std::size_t limit = static_cast<std::size_t>(std::max(1000, m_pendingLimit.load()));
            while (m_pendingEvents.size() > limit)
            {
                m_pendingEvents.pop_front();
                m_r3DroppedCount.fetch_add(1ULL);
            }
        }

        if ((readResult.responseFlags & KSWORD_ARK_CALLBACK_MONITOR_READ_FLAG_MORE_AVAILABLE) == 0UL)
        {
            std::unique_lock<std::mutex> lock(m_pendingMutex);
            m_workerWake.wait_for(lock, std::chrono::milliseconds(80), [this]() {
                return m_workerStop.load();
            });
        }
    }
}

void KernelCallbackMonitorWidget::recordWorkerFailure(
    const std::string& message,
    const bool unsupported)
{
    std::lock_guard<std::mutex> lock(m_pendingMutex);
    m_workerError = message;
    m_workerUnsupported = unsupported;
}

void KernelCallbackMonitorWidget::flushPendingEvents()
{
    std::string workerError;
    bool workerUnsupported = false;
    {
        std::lock_guard<std::mutex> lock(m_pendingMutex);
        workerError = m_workerError;
        workerUnsupported = m_workerUnsupported;
        m_workerError.clear();
    }
    if (!workerError.empty())
    {
        m_lastDisplayedError = workerUnsupported
            ? QStringLiteral("当前驱动不支持内核回调监控，请更新驱动")
            : QString::fromStdString(workerError);
        updateActionState();
    }

    if (m_paused.load() ||
        ks::ui::IsTableUiCommitBlockedByContextMenu(QList<QTableView*>{ m_eventTable }))
    {
        updateStatusLabel();
        return;
    }

    std::vector<ksword::ark::CallbackMonitorEventRow> batch;
    {
        std::lock_guard<std::mutex> lock(m_pendingMutex);
        const std::size_t batchSize = std::min<std::size_t>(m_pendingEvents.size(), 1000U);
        batch.reserve(batchSize);
        for (std::size_t index = 0U; index < batchSize; ++index)
        {
            batch.push_back(std::move(m_pendingEvents.front()));
            m_pendingEvents.pop_front();
        }
    }
    if (!batch.empty())
    {
        const bool keepBottom = m_keepBottomCheck->isChecked() &&
            m_eventTable->verticalScrollBar()->value() >=
                m_eventTable->verticalScrollBar()->maximum() - 2;
        m_eventModel->appendRows(std::move(batch), m_maxRowsSpin->value());
        if (keepBottom)
        {
            m_eventTable->scrollToBottom();
        }
        applyFilters();
    }
    updateStatusLabel();
}

void KernelCallbackMonitorWidget::applyFilters()
{
    m_filterModel->setFilters(
        m_categoryFilterCombo->currentData().toUInt(),
        m_operationFilterEdit->text(),
        m_pidFilterEdit->text(),
        m_processFilterEdit->text(),
        m_pathFilterEdit->text(),
        m_resultFilterEdit->text(),
        m_regexCheck->isChecked());
    m_filterStatusLabel->setText(m_filterModel->invalidRegex()
        ? ks::i18n::sourceText(QStringLiteral("正则表达式无效"))
        : ks::i18n::sourceText(QStringLiteral("筛选结果：%1 / %2"))
            .arg(m_filterModel->rowCount())
            .arg(m_eventModel->rowCount()));
}

void KernelCallbackMonitorWidget::updateActionState()
{
    const bool running = m_captureRunning.load();
    const bool paused = m_paused.load();
    m_startButton->setEnabled(!running || paused);
    m_stopButton->setEnabled(running || m_driverCaptureActive.load());
    m_pauseButton->setEnabled(running);
    m_pauseButton->setIcon(QIcon(paused
        ? QStringLiteral(":/Icon/process_start.svg")
        : QStringLiteral(":/Icon/process_pause.svg")));
    m_pauseButton->setToolTip(ks::i18n::sourceText(paused
        ? QStringLiteral("继续把后台事件提交到表格")
        : QStringLiteral("暂停事件入表，后台继续读取")));
    const QList<QCheckBox*> categoryChecks{
        m_processCheck, m_threadCheck, m_imageCheck, m_registryCheck, m_objectCheck, m_fileCheck
    };
    for (QCheckBox* checkBox : categoryChecks)
    {
        checkBox->setEnabled(!running);
    }
}

void KernelCallbackMonitorWidget::updateStatusLabel()
{
    std::size_t pendingCount = 0U;
    {
        std::lock_guard<std::mutex> lock(m_pendingMutex);
        pendingCount = m_pendingEvents.size();
    }
    QString stateText = ks::i18n::sourceText(QStringLiteral("空闲"));
    if (m_captureRunning.load())
    {
        stateText = ks::i18n::sourceText(
            m_paused.load() ? QStringLiteral("暂停显示") : QStringLiteral("正在采集"));
    }
    if (!m_lastDisplayedError.isEmpty())
    {
        stateText = ks::i18n::sourceText(QStringLiteral("错误：%1"))
            .arg(ks::i18n::sourceText(m_lastDisplayedError));
    }
    m_statusLabel->setText(ks::i18n::sourceText(QStringLiteral(
        "● %1 | 类别 0x%2 | R0 容量 %3 | 最新 %4 | R0 丢弃 %5 | 游标丢失 %6 | R3 丢弃 %7 | 待提交 %8 | 行 %9 / %10"))
        .arg(stateText)
        .arg(m_activeCategoryMask.load(), 2, 16, QLatin1Char('0'))
        .arg(m_ringCapacity.load())
        .arg(m_latestSequence.load())
        .arg(m_r0DroppedCount.load())
        .arg(m_cursorLostCount.load())
        .arg(m_r3DroppedCount.load())
        .arg(pendingCount)
        .arg(m_filterModel->rowCount())
        .arg(m_eventModel->rowCount()));
}

void KernelCallbackMonitorWidget::updateDetailPanel()
{
    const QModelIndex currentIndex = m_eventTable->currentIndex();
    if (!currentIndex.isValid())
    {
        m_detailEdit->clear();
        return;
    }
    const QModelIndex sourceIndex = m_filterModel->mapToSource(currentIndex);
    const auto* row = m_eventModel->rowAt(sourceIndex.row());
    if (row == nullptr)
    {
        m_detailEdit->clear();
        return;
    }

    const QString detailText = ks::i18n::sourceText(QStringLiteral(
        "序号：%1\n时间：%2\n类别：%3\n操作：%4\n来源 PID/TID：%5\n目标 PID/TID：%6\n父 PID：%7\nSession：%8\n结果：%9\n原始/最终访问：0x%10 / 0x%11\n对象类型：%12\nDetailCode：0x%13\n地址/大小：0x%14 / 0x%15\n进程：%16\n路径：%17\n事件标志：0x%18"))
        .arg(row->sequence)
        .arg(callbackTimeText(row->timeUtc100ns))
        .arg(ks::i18n::sourceText(callbackCategoryText(row->category)))
        .arg(ks::i18n::sourceText(callbackOperationText(*row)))
        .arg(callbackPidTidText(*row))
        .arg(callbackTargetText(*row))
        .arg(row->parentProcessId)
        .arg(row->sessionId)
        .arg(callbackResultText(*row))
        .arg(row->originalAccess, 8, 16, QLatin1Char('0'))
        .arg(row->desiredAccess, 8, 16, QLatin1Char('0'))
        .arg(row->objectType)
        .arg(row->detailCode, 8, 16, QLatin1Char('0'))
        .arg(row->address, 0, 16)
        .arg(row->regionSize, 0, 16)
        .arg(QString::fromStdWString(row->processName))
        .arg(QString::fromStdWString(row->path))
        .arg(row->flags, 8, 16, QLatin1Char('0'));
    m_detailEdit->setPlainText(detailText);
}

void KernelCallbackMonitorWidget::exportVisibleRows()
{
    const QString outputPath = QFileDialog::getSaveFileName(
        this,
        ks::i18n::sourceText(QStringLiteral("导出内核回调事件")),
        QStringLiteral("kernel-callback-events.csv"),
        ks::i18n::sourceText(QStringLiteral("CSV 文件 (*.csv);;所有文件 (*.*)")));
    if (outputPath.isEmpty())
    {
        return;
    }
    QSaveFile outputFile(outputPath);
    if (!outputFile.open(QIODevice::WriteOnly | QIODevice::Text))
    {
        m_lastDisplayedError = QStringLiteral("无法创建导出文件");
        updateStatusLabel();
        return;
    }

    QTextStream stream(&outputFile);
    stream.setEncoding(QStringConverter::Utf8);
    stream << QChar(0xFEFF);
    for (int column = 0; column < CallbackColumnCount; ++column)
    {
        if (column != 0) stream << QLatin1Char(',');
        stream << QLatin1Char('"')
            << m_filterModel->headerData(column, Qt::Horizontal, Qt::DisplayRole)
                .toString().replace(QLatin1Char('"'), QStringLiteral("\"\""))
            << QLatin1Char('"');
    }
    stream << QLatin1Char('\n');
    for (int row = 0; row < m_filterModel->rowCount(); ++row)
    {
        for (int column = 0; column < CallbackColumnCount; ++column)
        {
            if (column != 0) stream << QLatin1Char(',');
            QString text = m_filterModel->index(row, column).data(Qt::DisplayRole).toString();
            text.replace(QLatin1Char('"'), QStringLiteral("\"\""));
            stream << QLatin1Char('"') << text << QLatin1Char('"');
        }
        stream << QLatin1Char('\n');
    }
    if (!outputFile.commit())
    {
        m_lastDisplayedError = QStringLiteral("写入导出文件失败");
        updateStatusLabel();
    }
}
