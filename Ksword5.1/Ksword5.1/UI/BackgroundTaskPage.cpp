#include "../Framework/ProgressDockWidget.h"
#include "RuntimeControlPages.h"
#include "../Framework/BackgroundTaskRegistry.h"
#include "../Internationalization/LanguageManager.h"
#include "SecondaryPageLayout.h"
#include "TablePresentation.h"
#include "PageControlStyle.h"
#include "ToolbarMetrics.h"
#include "FlowLayout.h"
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
    struct BackgroundTaskPage::State
    {
        VisibleTableWidget* table = nullptr;
        QLineEdit* search = nullptr;
        QComboBox* filter = nullptr;
        QLabel *summary = nullptr, *selection = nullptr, *status = nullptr;
        QSpinBox* interval = nullptr;
        QPushButton *save = nullptr, *defaults = nullptr;
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
        m->table = new VisibleTableWidget(this);
        m->table->setObjectName(QStringLiteral("ks_background_task_list"));
        m->table->setColumnCount(5);
        m->table->setHorizontalHeaderLabels({i18n::sourceText(QStringLiteral("任务")), i18n::sourceText(QStringLiteral("分组")),
            i18n::sourceText(QStringLiteral("状态")), i18n::sourceText(QStringLiteral("间隔(ms)")), i18n::sourceText(QStringLiteral("操作"))});
        m->table->setSelectionBehavior(QAbstractItemView::SelectRows);
        m->table->setSelectionMode(QAbstractItemView::SingleSelection);
        m->table->setEditTriggers(QAbstractItemView::NoEditTriggers);
        m->table->verticalHeader()->hide();
        m->table->verticalHeader()->setDefaultSectionSize(36);
        m->table->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
        for (int col = 1; col < 5; ++col) m->table->horizontalHeader()->setSectionResizeMode(col, QHeaderView::ResizeToContents);
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
        m->interval = new QSpinBox(controls);
        m->interval->setSuffix(i18n::sourceText(QStringLiteral(" 毫秒")));
        m->interval->setMinimumWidth(140);
        m->save = new QPushButton(i18n::sourceText(QStringLiteral("应用间隔")), controls);
        m->defaults = new QPushButton(i18n::sourceText(QStringLiteral("恢复默认")), controls);
        row->addWidget(m->interval); row->addWidget(m->save); row->addWidget(m->defaults);
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
        m->timer = new QTimer(this);
        m->timer->setInterval(1000);
        connect(m->timer, &QTimer::timeout, this, [this]() { refresh(); });
        selectTask();
    }
    BackgroundTaskPage::~BackgroundTaskPage() = default;
    void BackgroundTaskPage::showEvent(QShowEvent* event) { QWidget::showEvent(event); refresh(); m->timer->start(); }
    void BackgroundTaskPage::hideEvent(QHideEvent* event) { m->timer->stop(); QWidget::hideEvent(event); }

    void BackgroundTaskPage::refresh()
    {
        auto rows = BackgroundTaskRegistry::instance().snapshot();
        bool changed = rows.size() != m->rows.size();
        if (!changed) for (int i = 0; i < rows.size(); ++i) if (rows[i].id != m->rows[i].id) changed = true;
        m->rows = std::move(rows);
        const QSignalBlocker block(m->table);
        if (changed) { m->table->clearContents(); m->table->setRowCount(m->rows.size()); }
        int visible = 0;
        for (int row = 0; row < m->rows.size(); ++row)
        {
            const auto& task = m->rows[row];
            const bool running = task.active || task.inFlight;
            const QString state = task.paused ? i18n::sourceText(QStringLiteral("已暂停"))
                : running ? i18n::sourceText(QStringLiteral("运行中")) : i18n::sourceText(QStringLiteral("待命"));
            const QStringList cells{i18n::displayText(task.title), i18n::displayText(task.group), state,
                task.intervalMs ? QString::number(task.intervalMs) : i18n::sourceText(QStringLiteral("会话控制"))};
            for (int col = 0; col < cells.size(); ++col)
            {
                auto* item = m->table->item(row, col);
                if (!item) { item = new QTableWidgetItem(); m->table->setItem(row, col, item); }
                if (item->text() != cells[col]) item->setText(cells[col]);
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
            auto* action = qobject_cast<QPushButton*>(m->table->cellWidget(row, 4));
            if (!action)
            {
                action = new QPushButton(m->table);
                m->table->setCellWidget(row, 4, action);
                connect(action, &QPushButton::clicked, this, [this, id = task.id, title = task.title]() {
                    auto& registry = BackgroundTaskRegistry::instance();
                    QString error;
                    if (!registry.setPaused(id, !registry.isPaused(id), &error)) m->status->setText(error);
                    else m->status->setText(i18n::displayText(title) + QStringLiteral("：")
                        + i18n::sourceText(registry.isPaused(id) ? QStringLiteral("已暂停") : QStringLiteral("恢复")));
                    refresh();
                });
            }
            action->setText(!task.canPause ? i18n::sourceText(QStringLiteral("不可暂停"))
                : task.paused ? i18n::sourceText(QStringLiteral("恢复")) : i18n::sourceText(QStringLiteral("暂停")));
            action->setEnabled(task.canPause && (running || task.paused));
            action->setToolTip(i18n::displayText(task.restriction));
            const int filter = m->filter->currentIndex();
            const bool shown = cells.join(QLatin1Char(' ')).contains(m->search->text().trimmed(), Qt::CaseInsensitive)
                && (filter == 0 || (filter == 1 && running && !task.paused) || (filter == 2 && task.paused)
                    || (filter == 3 && !running && !task.paused));
            m->table->setRowHidden(row, !shown);
            if (shown) ++visible;
            if (changed && task.id == m->id && shown) m->table->selectRow(row);
        }
        m->summary->setText(i18n::sourceText(QStringLiteral("显示 %1 / %2 项")).arg(visible).arg(m->rows.size()));
        if (changed)
        {
            bool present = false;
            for (const auto& task : m->rows) if (task.id == m->id) present = true;
            if (!present) { m->table->clearSelection(); m->id.clear(); selectTask(); }
        }
    }
    void BackgroundTaskPage::selectTask()
    {
        const auto selected = m->table->selectionModel()->selectedRows();
        m->id = selected.isEmpty() ? QString{} : m->table->item(selected.front().row(), 0)->data(Qt::UserRole).toString();
        m->loading = true;
        bool found = false;
        for (const auto& task : m->rows)
        {
            if (task.id != m->id) continue;
            found = true;
            m->selection->setText(i18n::displayText(task.title));
            m->interval->setSpecialValueText(task.intervalMs ? QString{} : i18n::sourceText(QStringLiteral("会话控制")));
            m->interval->setRange(task.minimumIntervalMs, task.maximumIntervalMs);
            m->interval->setValue(m->drafts.value(task.id, task.intervalMs));
            m->interval->setEnabled(task.canChangeInterval);
            m->save->setEnabled(task.canChangeInterval && m->drafts.contains(task.id));
            m->defaults->setEnabled(task.canChangeInterval);
            m->status->setText(m->drafts.contains(task.id) ? i18n::sourceText(QStringLiteral("间隔尚未应用。"))
                : i18n::displayText(task.restriction));
            break;
        }
        if (!found)
        {
            m->selection->setText(i18n::sourceText(QStringLiteral("选择任务可调整间隔；暂停与恢复直接在对应行操作。")));
            m->interval->setEnabled(false); m->save->setEnabled(false); m->defaults->setEnabled(false); m->status->clear();
        }
        m->loading = false;
    }
    void BackgroundTaskPage::apply(int operation)
    {
        const QString id = m->id;
        QString error;
        auto& registry = BackgroundTaskRegistry::instance();
        const bool ok = operation == 2 ? registry.setInterval(id, m->interval->value(), &error) : registry.restoreDefault(id, &error);
        if (ok) m->drafts.remove(id);
        refresh(); selectTask();
        m->status->setText(ok ? i18n::sourceText(QStringLiteral("间隔已应用。")) : error);
    }
}
