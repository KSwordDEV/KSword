#include "ProcessDetectionPane.h"
#include "ProcessDetectionMethods.h"
#include "ProcessDetectionSelector.h"
#include "../Internationalization/LanguageManager.h"
#include "../UI/AsyncOperation.h"
#include "../UI/DetailLayoutHost.h"
#include "../UI/DetailLayoutRegistry.h"
#include "../UI/FlatButtonTheme.h"
#include "../UI/FlatTableModel.h"
#include "../UI/PageControlStyle.h"
#include "../UI/ParameterWorkspace.h"
#include "../UI/ResultTableHost.h"
#include "../UI/StructuredFieldView.h"
#include "../theme.h"

#include <QHash>
#include <QHeaderView>
#include <QItemSelectionModel>
#include <QLabel>
#include <QPushButton>
#include <QSplitter>
#include <QTabWidget>
#include <QVBoxLayout>

namespace ksword::detection
{
    namespace
    {
        using TableModel = ks::ui::FlatTableModel<QStringList>;
        using Identity = QPair<quint32, quint64>;

        QString statusName(Status status)
        {
            switch (status)
            {
            case Status::Complete: return QStringLiteral("完成");
            case Status::Partial: return QStringLiteral("部分完成");
            case Status::Unavailable: return QStringLiteral("不可用");
            case Status::Failed: return QStringLiteral("失败");
            case Status::Cancelled: return QStringLiteral("已取消");
            }
            return {};
        }

        QString objectText(quint64 value)
        {
            return value ? QStringLiteral("0x%1").arg(value, 0, 16) : QString();
        }

        struct DisplaySnapshot
        {
            QString started;
            std::vector<QStringList> reports;
            std::vector<QStringList> evidence;
            QHash<Identity, QStringList> processMethods;
            int usable = 0;
            int complete = 0;
        };

        // Build rows and the process tooltip index on the same worker as acquisition.
        // Raw R0 matrices remain available in the dedicated Cross-View page.
        DisplaySnapshot present(const ScanResult& scan,
            const ks::i18n::SourceTextSnapshot& language, const ks::ui::AsyncOperationToken& token)
        {
            DisplaySnapshot result;
            result.started = scan.startedUtc.toLocalTime().toString(Qt::ISODateWithMs);
            const auto catalog = Methods();
            QHash<MethodMask, QString> names;
            auto methodNames = [&](MethodMask mask)
            {
                const auto existing = names.constFind(mask);
                if (existing != names.constEnd()) return *existing;
                QStringList selected;
                for (const auto& method : catalog)
                    if (method.bit & mask) selected.append(language.sourceText(method.name));
                return names.insert(mask, selected.join(QStringLiteral(", "))).value();
            };
            for (const auto& report : scan.reports)
            {
                result.usable += report.status == Status::Complete || report.status == Status::Partial;
                result.complete += report.status == Status::Complete;
                result.reports.push_back({methodNames(report.method), statusName(report.status),
                    QString::number(report.elapsedMs), QString::number(report.count), report.detail});
            }
            result.evidence.reserve(static_cast<size_t>(scan.evidence.size()));
            std::vector<QStringList> ordinary;
            for (const auto& entry : scan.evidence)
            {
                if (token.isCanceled()) return result;
                const QString methods = methodNames(entry.methods);
                QString category = QStringLiteral("进程线索");
                if (!entry.category.isEmpty()) category = entry.category;
                else if (entry.historical) category = QStringLiteral("历史记录");
                else if (entry.lifetimeUnknown) category = QStringLiteral("生命周期未核实");
                else if (!entry.scope.isEmpty()) category = QStringLiteral("离线证据");
                else if (entry.absentFromBaseline) category = QStringLiteral("未在基线中观察到");
                auto& rows = entry.absentFromBaseline ? result.evidence : ordinary;
                rows.push_back({category, entry.scope.isEmpty() ? QStringLiteral("本机") : entry.scope,
                    entry.pid || (entry.methods & ProcessBaseline) ? QString::number(entry.pid) : QString(),
                    QString(), entry.image, objectText(entry.objectAddress),
                    entry.creationTime100ns ? QString::number(entry.creationTime100ns) : QString(),
                    methods, entry.detail});
                if (entry.scope.isEmpty() && !entry.historical && !entry.lifetimeUnknown && entry.pid && entry.creationTime100ns)
                {
                    auto& sources = result.processMethods[{entry.pid, entry.creationTime100ns}];
                    if (!sources.contains(methods)) sources.append(methods);
                }
            }
            const auto addNative = [&](const auto& row, QString tid, MethodMask group)
            {
                if (!ComparableAnomalies(scan, row)) return;
                const auto detail = language.sourceText(QStringLiteral("来源掩码 %1，异常掩码 %2。%3"))
                    .arg(objectText(row.sourceMask), objectText(row.anomalyFlags), QString::fromStdString(row.detail));
                result.evidence.push_back({QStringLiteral("内核结构差异"), QStringLiteral("本机"),
                    QString::number(row.processId), std::move(tid), QString::fromStdString(row.imageName),
                    objectText(row.objectAddress), QString(), methodNames(scan.selected & group), detail});
            };
            if (scan.processCrossView)
                for (const auto& row : scan.processCrossView->entries)
                {
                    if (token.isCanceled()) return result;
                    addNative(row, {}, ProcessKernelMethods);
                }
            if (scan.threadCrossView)
                for (const auto& row : scan.threadCrossView->entries)
                {
                    if (token.isCanceled()) return result;
                    addNative(row, QString::number(row.threadId), ThreadKernelMethods);
                }
            // Surface discrepancies before ordinary baseline rows on large hosts.
            result.evidence.insert(result.evidence.end(), std::make_move_iterator(ordinary.begin()),
                std::make_move_iterator(ordinary.end()));
            return result;
        }

        struct ResultTable
        {
            ks::ui::TableActionTableView* view;
            TableModel* model;
            ks::ui::ResultTableHost* host;
        };

        ResultTable makeTable(QWidget* parent, const QStringList& titles, const QStringList& ids)
        {
            auto* view = new ks::ui::TableActionTableView(parent);
            view->setSelectionBehavior(QAbstractItemView::SelectRows);
            view->setSelectionMode(QAbstractItemView::ExtendedSelection);
            view->setEditTriggers(QAbstractItemView::NoEditTriggers);
            view->setAlternatingRowColors(true);
            view->verticalHeader()->hide();
            std::vector<TableModel::ColumnSpec> columns;
            QList<ks::ui::ResultTableColumn> bindings;
            for (int i = 0; i < titles.size(); ++i)
            {
                columns.push_back({titles.at(i)});
                bindings.append({i, ids.at(i)});
            }
            auto* model = new TableModel(std::move(columns),
                [](const QStringList& row, int column, int role) -> QVariant
                {
                    if (role == Qt::DisplayRole || role == Qt::ToolTipRole) return row.at(column);
                    if (role == Qt::ForegroundRole && column == 0 &&
                        (row.front() == QStringLiteral("未在基线中观察到") || row.front() == QStringLiteral("内核结构差异")))
                        return KswordTheme::WarningColor();
                    return {};
                }, view);
            auto* host = ks::ui::ResultTableHost::ensure(view);
            ks::ui::ResultTableCapabilities capabilities;
            capabilities.actionBar = ks::ui::TableActionBarMode::Compact;
            host->bindModel(model, bindings, capabilities);
            view->horizontalHeader()->setStretchLastSection(true);
            return {view, model, host};
        }
    }

    struct ProcessDetectionPane::State
    {
        ks::ui::AsyncOperation* operation = nullptr;
        ProcessDetectionSelector* selector = nullptr;
        QPushButton* run = nullptr;
        QPushButton* cancel = nullptr;
        QLabel* status = nullptr;
        QLabel* evidenceCaption = nullptr;
        QTabWidget* tabs = nullptr;
        ResultTable findings{};
        ResultTable receipts{};
        ks::ui::StructuredFieldView* details = nullptr;
        QString evidenceStarted;
        QHash<Identity, QStringList> processMethods;
        std::function<void()> reportChanged;
        bool cancelRequested = false;

        void showDetail()
        {
            const auto& table = tabs->currentWidget() == findings.view ? findings : receipts;
            const QModelIndex current = table.view->currentIndex();
            ks::ui::FieldDocument doc;
            if (current.isValid())
            {
                for (int column = 0; column < current.model()->columnCount(); ++column)
                {
                    const auto value = current.siblingAtColumn(column).data().toString();
                    if (!value.isEmpty()) doc.field(current.model()->headerData(column, Qt::Horizontal).toString(), value);
                }
            }
            details->setDocument(doc);
        }
    };

    ProcessDetectionPane::ProcessDetectionPane(bool deep, QWidget* parent) : QWidget(parent), m_state(std::make_unique<State>())
    {
        auto& s = *m_state;
        auto* root = new QVBoxLayout(this);
        root->setContentsMargins(0, 0, 0, 0);
        auto* workspace = new ks::ui::ParameterWorkspace(this);
        workspace->useStackedLayout();
        root->addWidget(workspace);
        s.operation = new ks::ui::AsyncOperation(this);
        s.selector = new ProcessDetectionSelector(deep, this);
        auto* scope = new QHBoxLayout;
        scope->addWidget(s.selector);
        scope->addStretch();
        workspace->parameters()->addLayout(scope);
        s.run = new QPushButton(QStringLiteral("开始检测"), this);
        ks::ui::ApplyFlatButtonTheme(s.run, ks::ui::FlatButtonTone::Accent, ks::ui::FlatButtonAppearance::Solid);
        s.cancel = new QPushButton(QStringLiteral("取消"), this);
        s.cancel->setEnabled(false);
        workspace->actions()->addWidget(s.run);
        workspace->actions()->addWidget(s.cancel);
        workspace->actions()->addStretch();
        s.status = new QLabel(QStringLiteral("等待检测"), this);
        s.status->setWordWrap(true);
        s.status->setTextFormat(Qt::PlainText);
        s.status->setTextInteractionFlags(Qt::TextSelectableByMouse);
        workspace->results()->addWidget(s.status);
        auto* splitter = new QSplitter(Qt::Vertical, this);
        s.tabs = new QTabWidget(splitter);
        ks::ui::StylePageTabs(s.tabs);
        s.findings = makeTable(s.tabs, {QStringLiteral("类别"), QStringLiteral("采集范围"), QStringLiteral("PID"),
            QStringLiteral("TID"), QStringLiteral("映像"), QStringLiteral("对象地址"), QStringLiteral("创建时间 (FILETIME)"),
            QStringLiteral("检测方法"), QStringLiteral("说明")},
            {"kind", "scope", "pid", "tid", "image", "object", "creation", "methods", "detail"});
        s.receipts = makeTable(s.tabs, {QStringLiteral("检测方法"), QStringLiteral("状态"), QStringLiteral("耗时 (ms)"),
            QStringLiteral("记录数"), QStringLiteral("说明")}, {"method", "status", "elapsed", "count", "detail"});
        s.tabs->addTab(s.findings.view, QStringLiteral("证据线索"));
        s.tabs->addTab(s.receipts.view, QStringLiteral("方法回执"));
        s.details = new ks::ui::StructuredFieldView(splitter);
        splitter->addWidget(s.tabs);
        splitter->addWidget(s.details);
        splitter->setStretchFactor(0, 4);
        splitter->setStretchFactor(1, 1);
        auto* host = ks::ui::DetailLayoutRegistry::registerStructuredHost(
            s.findings.view, s.details, this, splitter, s.tabs, s.details);
        workspace->results()->addWidget(splitter, 1);
        s.evidenceCaption = new QLabel(this);
        s.evidenceCaption->setWordWrap(true);
        s.evidenceCaption->setTextFormat(Qt::PlainText);
        s.evidenceCaption->setTextInteractionFlags(Qt::TextSelectableByMouse);
        workspace->results()->addWidget(s.evidenceCaption);
        workspace->finish();
        connect(s.tabs, &QTabWidget::currentChanged, this, [this, host = QPointer<ks::ui::DetailLayoutHost>(host)] {
            auto& state = *m_state;
            const bool evidence = state.tabs->currentWidget() == state.findings.view;
            if (host) host->setTableView(evidence ? state.findings.view : state.receipts.view);
            state.evidenceCaption->setVisible(evidence);
            state.showDetail();
        });
        for (const auto& table : {s.findings, s.receipts})
            connect(table.view->selectionModel(), &QItemSelectionModel::currentChanged, this,
                [this] { m_state->showDetail(); });
        connect(s.run, &QPushButton::clicked, this, [this] { runSelected(); });
        connect(s.cancel, &QPushButton::clicked, this, [this] {
            m_state->cancelRequested = true;
            m_state->operation->cancel();
        });
        s.operation->setStateChangedCallback([this] {
            auto& state = *m_state;
            const bool running = state.operation->isInFlight();
            state.run->setEnabled(!running);
            state.cancel->setEnabled(running && !state.cancelRequested);
            if (state.cancelRequested)
                state.status->setText(running ? QStringLiteral("正在取消检测…") : QStringLiteral("检测已取消"));
        });
    }

    ProcessDetectionPane::~ProcessDetectionPane()
    {
        m_state->operation->close();
    }

    void ProcessDetectionPane::chooseMethods()
    {
        m_state->selector->click();
    }

    void ProcessDetectionPane::runSelected()
    {
        auto& s = *m_state;
        if (s.operation->isInFlight()) return;
        const auto selected = s.selector->selectedMethods();
        if (!selected)
        {
            s.status->setText(QStringLiteral("请先选择检测方法。"));
            return;
        }
        struct Request { MethodMask methods; ScanInputs inputs; ks::i18n::SourceTextSnapshot language; };
        s.cancelRequested = false;
        s.status->setText(QStringLiteral("正在采集所选方法的证据…"));
        s.operation->submit<Request, std::shared_ptr<DisplaySnapshot>>(
            {selected, s.selector->scanInputs(), ks::i18n::LanguageManager::instance().sourceTextSnapshot()},
            [](const Request& request, const ks::ui::AsyncOperationToken& token) {
                auto scan = Run(request.methods, [&token] { return token.isCanceled(); }, request.inputs);
                return std::make_shared<DisplaySnapshot>(present(scan, request.language, token));
            },
            [this](const std::shared_ptr<DisplaySnapshot>& result, std::uint64_t generation) {
                const QPointer<ProcessDetectionPane> guard(this);
                const auto apply = [guard, result, generation] {
                    if (!guard || !guard->m_state->operation->isCurrent(generation)) return;
                    auto& state = *guard->m_state;
                    ks::ui::DetailLayoutRegistry::prepareDataRebuild(state.details);
                    const int count = static_cast<int>(result->reports.size());
                    state.receipts.model->setRows(std::move(result->reports));
                    if (result->usable > 0)
                    {
                        const auto evidenceCount = result->evidence.size();
                        state.findings.model->setRows(std::move(result->evidence));
                        state.evidenceStarted = result->started;
                        state.processMethods = std::move(result->processMethods);
                        state.evidenceCaption->setText(ks::i18n::sourceText(QStringLiteral("证据采样时间 %1，线索 %2 条。"))
                            .arg(result->started).arg(evidenceCount));
                    }
                    state.status->setText(ks::i18n::sourceText(QStringLiteral("%1　完整返回 %2/%3 项方法，逐项耗时及诊断见方法回执。"))
                        .arg(result->started).arg(result->complete).arg(count));
                    if (result->usable == 0) state.tabs->setCurrentWidget(state.receipts.view);
                    state.showDetail();
                    if (state.reportChanged && result->usable) state.reportChanged();
                };
                if (ks::ui::ResultTableHost::deferGroupIfBlocked(this, QStringLiteral("process-detection-apply"),
                    {m_state->findings.host, m_state->receipts.host}, [guard, generation, apply] {
                        apply();
                        if (guard) guard->m_state->operation->completeDeferred(generation);
                    })) return false;
                apply();
                return true;
            },
            [this](std::exception_ptr) { m_state->status->setText(QStringLiteral("检测中断，请重试。")); });
    }

    QString ProcessDetectionPane::evidenceForProcess(quint32 pid, quint64 creationTime100ns) const
    {
        const auto found = m_state->processMethods.constFind({pid, creationTime100ns});
        if (found == m_state->processMethods.constEnd()) return {};
        return ks::i18n::sourceText(QStringLiteral("检测证据（%1）：%2"))
            .arg(m_state->evidenceStarted, found->join(QStringLiteral(", ")));
    }

    void ProcessDetectionPane::setReportChanged(std::function<void()> callback)
    {
        m_state->reportChanged = std::move(callback);
    }
}
