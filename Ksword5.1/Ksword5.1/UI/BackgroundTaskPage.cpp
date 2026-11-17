#include "../Framework/ProgressDockWidget.h"
#include "RuntimeControlPages.h"
#include "../Framework/BackgroundTaskRegistry.h"
#include "../Internationalization/LanguageManager.h"
#include "SecondaryPageLayout.h"
#include "TablePresentation.h"
#include "PageControlStyle.h"
#include "ToolbarMetrics.h"
#include "FlowLayout.h"
#include "FlatButtonTheme.h"
#include "VisibleTableWidget.h"
#include "UI_All.h"
#include <QComboBox>
#include <QHeaderView>
#include <QHideEvent>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QShowEvent>
#include <QSignalBlocker>
#include <QSpinBox>
#include <QTimer>
#include <QVBoxLayout>

namespace ks::ui
{
    namespace
    {
        class TaskListItem final : public QTableWidgetItem
        {
        public:
            bool operator<(const QTableWidgetItem& other) const override
            {
                if (data(Qt::UserRole + 1).isValid() && other.data(Qt::UserRole + 1).isValid())
                    return data(Qt::UserRole + 1).toDouble() < other.data(Qt::UserRole + 1).toDouble();
                return QTableWidgetItem::operator<(other);
            }
        };
    }
    struct BackgroundTaskPage::State
    {
        VisibleTableWidget* table = nullptr;
        QLineEdit* search = nullptr;
        QComboBox* filter = nullptr;
        QLabel *summary = nullptr, *selection = nullptr, *status = nullptr;
        QLabel* cpuSummary = nullptr;
        QSpinBox* interval = nullptr;
        QPushButton *save = nullptr, *defaults = nullptr, *pause = nullptr, *resume = nullptr;
        QPushButton *analyze = nullptr, *reset = nullptr;
        QTimer* timer = nullptr;
        QString id;
        QVector<BackgroundTaskRegistry::Snapshot> rows;
        QHash<QString, int> drafts;
        bool loading = false;
    };

    TaskManagerDialog::TaskManagerDialog(QWidget* parent) : QDialog(parent)
    {
        StyleSecondaryManagerWindow(this);
        setObjectName(QStringLiteral("ks_task_manager"));
        setWindowTitle(i18n::sourceText(QStringLiteral("任务管理器")));
        setModal(false);
        applyResponsiveWindowGeometry(this, parent, QSize(1000, 680), QSize(680, 480));
        auto* root = new QVBoxLayout(this);
        root->setContentsMargins(6, 6, 6, 6);
        m_tasks = new ProgressDockWidget(this, true);
        root->addWidget(m_tasks, 1);
    }
    void TaskManagerDialog::showBackgroundTasks() { m_tasks->showBackgroundTasks(); }

    BackgroundTaskPage::BackgroundTaskPage(QWidget* parent) : QWidget(parent), m(std::make_unique<State>())
    {
        setObjectName(QStringLiteral("ks_background_task_page"));
        auto* root = new QVBoxLayout(this);
        root->setContentsMargins(0, 6, 0, 0);
        root->setSpacing(8);
        auto* toolbar = new QHBoxLayout();
        m->search = new QLineEdit(this);
        m->search->setPlaceholderText(i18n::sourceText(QStringLiteral("搜索任务")));
        m->search->setClearButtonEnabled(true);
        StyleSearchField(m->search);
        m->filter = new QComboBox(this);
        m->filter->addItems({i18n::sourceText(QStringLiteral("全部状态")), i18n::sourceText(QStringLiteral("运行中")),
            i18n::sourceText(QStringLiteral("已暂停")), i18n::sourceText(QStringLiteral("待命"))});
        toolbar->addWidget(m->search, 1);
        toolbar->addWidget(m->filter);
        NormalizeToolbarRow(toolbar);
        root->addLayout(toolbar);
        m->summary = new QLabel(this);
        root->addWidget(m->summary);
        auto* analysis = new QWidget(this);
        auto* analysisRow = new FlowLayout(analysis, 0, 8, 6);
        m->analyze = new QPushButton(i18n::sourceText(QStringLiteral("开始 CPU 分析")), analysis);
        m->reset = new QPushButton(i18n::sourceText(QStringLiteral("重新统计")), analysis);
        m->cpuSummary = new QLabel(analysis);
        analysisRow->addWidget(m->analyze); analysisRow->addWidget(m->reset);
        NormalizeToolbarLayout(analysisRow);
        const QString cpuHint = i18n::sourceText(QStringLiteral("进程占用按全部逻辑处理器归一化，显示本次分析期间的平均值。任务 CPU 时间只计入已完成的定时回调和已接入的后台工作；独立原生会话未测量，合计不等于整个进程。离开此页会停止分析。"));
        m->analyze->setToolTip(cpuHint);
        m->cpuSummary->setToolTip(cpuHint);
        root->addWidget(analysis);
        m->cpuSummary->setWordWrap(true);
        root->addWidget(m->cpuSummary);
        m->table = new VisibleTableWidget(this);
        m->table->setObjectName(QStringLiteral("ks_background_task_list"));
        m->table->setColumnCount(7);
        m->table->setHorizontalHeaderLabels({i18n::sourceText(QStringLiteral("任务")), i18n::sourceText(QStringLiteral("分组")),
            i18n::sourceText(QStringLiteral("状态")), i18n::sourceText(QStringLiteral("间隔(ms)")),
            i18n::sourceText(QStringLiteral("CPU 时间(ms)")), i18n::sourceText(QStringLiteral("后台 CPU(ms)")),
            i18n::sourceText(QStringLiteral("完成片段"))});
        m->table->setSelectionBehavior(QAbstractItemView::SelectRows);
        m->table->setSelectionMode(QAbstractItemView::SingleSelection);
        m->table->setEditTriggers(QAbstractItemView::NoEditTriggers);
        m->table->verticalHeader()->hide();
        m->table->verticalHeader()->setDefaultSectionSize(30);
        m->table->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
        for (int col = 1; col < 7; ++col) m->table->horizontalHeader()->setSectionResizeMode(col, QHeaderView::ResizeToContents);
        SetTableActionBarMode(m->table, TableActionBarMode::None);
        ApplyTablePresentation(m->table);
        root->addWidget(m->table, 1);
        auto* footer = new QWidget(this);
        auto* footerLayout = new QVBoxLayout(footer);
        footerLayout->setContentsMargins(0, 8, 0, 0);
        footerLayout->setSpacing(6);
        m->selection = new QLabel(footer);
        m->selection->setWordWrap(true);
        footerLayout->addWidget(m->selection);
        auto* controls = new QWidget(footer);
        auto* row = new FlowLayout(controls, 0, 8, 6);
        m->pause = new QPushButton(i18n::sourceText(QStringLiteral("暂停")), controls);
        m->resume = new QPushButton(i18n::sourceText(QStringLiteral("恢复")), controls);
        m->interval = new QSpinBox(controls);
        m->interval->setSuffix(i18n::sourceText(QStringLiteral(" 毫秒")));
        m->interval->setMinimumWidth(140);
        m->save = new QPushButton(i18n::sourceText(QStringLiteral("应用间隔")), controls);
        m->defaults = new QPushButton(i18n::sourceText(QStringLiteral("恢复默认")), controls);
        row->addWidget(m->pause); row->addWidget(m->resume);
        row->addWidget(m->interval); row->addWidget(m->save); row->addWidget(m->defaults);
        NormalizeToolbarLayout(row);
        ApplyFlatButtonTheme(m->save, FlatButtonTone::Accent, FlatButtonAppearance::Solid);
        footerLayout->addWidget(controls);
        m->status = new QLabel(footer);
        m->status->setWordWrap(true);
        footerLayout->addWidget(m->status);
        StyleSecondaryFooter(footer);
        root->addWidget(footer);
        connect(m->table, &QTableWidget::itemSelectionChanged, this, [this]() { selectTask(); });
        connect(m->search, &QLineEdit::textChanged, this, [this]() { refresh(); });
        connect(m->filter, &QComboBox::currentIndexChanged, this, [this]() { refresh(); });
        connect(m->interval, &QSpinBox::valueChanged, this, [this](int value) {
            if (m->loading || m->id.isEmpty()) return;
            m->drafts[m->id] = value;
            m->save->setEnabled(true);
            m->status->setText(i18n::sourceText(QStringLiteral("间隔尚未应用。")));
        });
        connect(m->save, &QPushButton::clicked, this, [this]() { apply(2); });
        connect(m->defaults, &QPushButton::clicked, this, [this]() { apply(3); });
        connect(m->pause, &QPushButton::clicked, this, [this]() { apply(0); });
        connect(m->resume, &QPushButton::clicked, this, [this]() { apply(1); });
        connect(m->analyze, &QPushButton::clicked, this, [this]() {
            auto& registry = BackgroundTaskRegistry::instance();
            if (registry.cpuAnalysis().active) registry.stopCpuAnalysis(); else registry.startCpuAnalysis();
            refresh();
        });
        connect(m->reset, &QPushButton::clicked, this, [this]() {
            BackgroundTaskRegistry::instance().startCpuAnalysis(); refresh();
        });
        m->timer = new QTimer(this);
        m->timer->setInterval(1000);
        connect(m->timer, &QTimer::timeout, this, [this]() { refresh(); });
        selectTask();
    }
    BackgroundTaskPage::~BackgroundTaskPage() { BackgroundTaskRegistry::instance().stopCpuAnalysis(); }
    void BackgroundTaskPage::showEvent(QShowEvent* event) { QWidget::showEvent(event); refresh(); m->timer->start(); }
    void BackgroundTaskPage::hideEvent(QHideEvent* event)
    {
        m->timer->stop(); BackgroundTaskRegistry::instance().stopCpuAnalysis(); QWidget::hideEvent(event);
    }

    void BackgroundTaskPage::refresh()
    {
        auto& registry = BackgroundTaskRegistry::instance();
        const auto analysis = registry.cpuAnalysis();
        m->analyze->setText(i18n::sourceText(analysis.active ? QStringLiteral("停止 CPU 分析") : QStringLiteral("开始 CPU 分析")));
        m->reset->setEnabled(analysis.started);
        m->cpuSummary->setText(!analysis.started ? i18n::sourceText(QStringLiteral("CPU 分析未开启"))
            : i18n::sourceText(QStringLiteral("%1 · %2 秒 · 进程平均 CPU %3 · CPU 时间 %4 ms"))
                .arg(i18n::sourceText(analysis.active ? QStringLiteral("统计中") : QStringLiteral("已停止")))
                .arg(analysis.seconds, 0, 'f', 1)
                .arg(analysis.processAvailable ? QString::number(analysis.processCpuPercent, 'f', 2) + QLatin1Char('%') : QStringLiteral("—"))
                .arg(analysis.processAvailable ? QString::number(analysis.processCpuMs, 'f', 2) : QStringLiteral("—")));
        auto rows = registry.snapshot();
        bool changed = rows.size() != m->rows.size();
        if (!changed) for (int i = 0; i < rows.size(); ++i) if (rows[i].id != m->rows[i].id) changed = true;
        m->rows = std::move(rows);
        const QSignalBlocker block(m->table);
        if (changed)
        {
            // A removed task must never leave its old row selected as another task.
            m->table->clearSelection();
            m->table->clearContents();
            m->table->setRowCount(m->rows.size());
        }
        QHash<QString, int> rowById;
        if (!changed) for (int row = 0; row < m->table->rowCount(); ++row)
            if (const auto* item = m->table->item(row, 0)) rowById.insert(item->data(Qt::UserRole).toString(), row);
        for (int col = 4; col < 7; ++col) m->table->setColumnHidden(col, !analysis.started);
        int visible = 0;
        for (int index = 0; index < m->rows.size(); ++index)
        {
            const auto& task = m->rows[index];
            const int row = changed ? index : rowById.value(task.id, index);
            const bool running = task.active || task.inFlight;
            const QString state = task.paused ? i18n::sourceText(QStringLiteral("已暂停"))
                : running ? i18n::sourceText(QStringLiteral("运行中")) : i18n::sourceText(QStringLiteral("待命"));
            const auto& cpu = task.cpu;
            const quint64 samples = cpu.samples[0] + cpu.samples[1] + cpu.samples[2];
            const quint64 failed = cpu.unavailable[0] + cpu.unavailable[1] + cpu.unavailable[2];
            const QString missing = i18n::sourceText(failed ? QStringLiteral("读取失败")
                : task.cpuSupported ? QStringLiteral("尚无样本") : QStringLiteral("未测量"));
            const QStringList cells{i18n::displayText(task.title), i18n::displayText(task.group), state,
                task.intervalMs ? QString::number(task.intervalMs) : i18n::sourceText(QStringLiteral("会话控制")),
                samples ? QString::number((cpu.time100ns[0] + cpu.time100ns[1] + cpu.time100ns[2]) / 10000.0, 'f', 3) : missing,
                cpu.samples[1] ? QString::number(cpu.time100ns[1] / 10000.0, 'f', 3) : QStringLiteral("—"),
                samples ? QString::number(samples) : QStringLiteral("—")};
            for (int col = 0; col < cells.size(); ++col)
            {
                auto* item = m->table->item(row, col);
                if (!item) { item = new TaskListItem(); m->table->setItem(row, col, item); }
                if (item->text() != cells[col]) item->setText(cells[col]);
                if (col == 3) item->setData(Qt::UserRole + 1, task.intervalMs);
                if (col == 4) item->setData(Qt::UserRole + 1, samples ? (cpu.time100ns[0] + cpu.time100ns[1] + cpu.time100ns[2]) / 10000.0 : -1.0);
                if (col == 5) item->setData(Qt::UserRole + 1, cpu.samples[1] ? cpu.time100ns[1] / 10000.0 : -1.0);
                if (col == 6) item->setData(Qt::UserRole + 1, samples ? static_cast<double>(samples) : -1.0);
                if (col >= 4)
                {
                    item->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
                    item->setToolTip(i18n::sourceText(QStringLiteral("界面派发：%1 ms\n后台工作：%2 ms\n结果提交：%3 ms\n未完成片段：%4\n读取失败片段：%5\n仅统计已接入且已完成的执行片段；0 可能低于系统 CPU 计时精度。"))
                        .arg(cpu.time100ns[0] / 10000.0, 0, 'f', 3).arg(cpu.time100ns[1] / 10000.0, 0, 'f', 3)
                        .arg(cpu.time100ns[2] / 10000.0, 0, 'f', 3).arg(task.cpuInFlight).arg(failed));
                }
                if (col == 0)
                {
                    item->setData(Qt::UserRole, task.id);
                    QString details = i18n::displayText(task.restriction);
                    if (task.intervalMs)
                    {
                        if (!details.isEmpty()) details += QLatin1Char('\n');
                        details += i18n::sourceText(QStringLiteral("派发次数：%1\n最近派发：%2"))
                            .arg(task.dispatches).arg(task.lastDispatch.isValid()
                                ? task.lastDispatch.toLocalTime().toString(QStringLiteral("HH:mm:ss")) : QStringLiteral("—"));
                    }
                    item->setToolTip(details);
                }
            }
            const int filter = m->filter->currentIndex();
            const bool shown = cells.join(QLatin1Char(' ')).contains(m->search->text().trimmed(), Qt::CaseInsensitive)
                && (filter == 0 || (filter == 1 && running && !task.paused) || (filter == 2 && task.paused)
                    || (filter == 3 && !running && !task.paused));
            m->table->setRowHidden(row, !shown);
            if (shown) ++visible;
            if (changed && task.id == m->id && shown) m->table->selectRow(row);
        }
        m->summary->setText(i18n::sourceText(QStringLiteral("显示 %1 / %2 项")).arg(visible).arg(m->rows.size()));
        selectTask(); // State can change outside this window; preserve drafts and feedback.
    }
    void BackgroundTaskPage::selectTask()
    {
        const auto selected = m->table->selectionModel()->selectedRows();
        const QString previous = m->id;
        m->id = selected.isEmpty() || m->table->isRowHidden(selected.front().row()) ? QString{}
            : m->table->item(selected.front().row(), 0)->data(Qt::UserRole).toString();
        m->loading = true;
        bool found = false;
        for (const auto& task : m->rows)
        {
            if (task.id != m->id) continue;
            found = true;
            m->selection->setText(i18n::displayText(task.title));
            m->interval->setSpecialValueText(task.intervalMs ? QString{} : i18n::sourceText(QStringLiteral("会话控制")));
            m->interval->setRange(task.minimumIntervalMs, task.maximumIntervalMs);
            const int interval = m->drafts.value(task.id, task.intervalMs);
            if (previous != m->id || m->interval->value() != interval) m->interval->setValue(interval);
            m->interval->setEnabled(task.canChangeInterval);
            m->save->setEnabled(task.canChangeInterval && m->drafts.contains(task.id));
            m->defaults->setEnabled(task.canChangeInterval);
            m->pause->setEnabled(task.canPause && !task.paused && (task.active || task.inFlight));
            m->resume->setEnabled(task.canPause && task.paused);
            for (auto* button : {m->pause, m->resume, m->save, m->defaults}) button->setToolTip(i18n::displayText(task.restriction));
            if (previous != m->id) m->status->setText(m->drafts.contains(task.id) ? i18n::sourceText(QStringLiteral("间隔尚未应用。"))
                : i18n::displayText(task.restriction));
            break;
        }
        if (!found)
        {
            m->selection->setText(i18n::sourceText(QStringLiteral("选择任务后，可在此暂停、恢复或调整间隔。")));
            m->interval->setEnabled(false); m->save->setEnabled(false); m->defaults->setEnabled(false);
            m->pause->setEnabled(false); m->resume->setEnabled(false);
            if (previous != m->id) m->status->clear();
        }
        m->loading = false;
    }
    void BackgroundTaskPage::apply(int operation)
    {
        const QString id = m->id;
        QString error;
        auto& registry = BackgroundTaskRegistry::instance();
        const bool ok = operation < 2 ? registry.setPaused(id, operation == 0, &error)
            : operation == 2 ? registry.setInterval(id, m->interval->value(), &error) : registry.restoreDefault(id, &error);
        if (ok && operation >= 2) m->drafts.remove(id);
        refresh();
        m->status->setText(ok ? i18n::sourceText(operation == 0 ? QStringLiteral("已暂停后续派发；在途工作仍会完成。")
            : operation == 1 ? QStringLiteral("已恢复，实际派发仍受原任务条件控制。") : QStringLiteral("间隔已应用。")) : error);
    }
}
