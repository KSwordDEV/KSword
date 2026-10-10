#include "../UI/StructuredFieldView.h"
#include "PrivilegeAccessPage.h"
#include "../UI/ToolbarMetrics.h"
#include "../UI/PrimaryPageStyle.h"
#include "PrivilegeAccessBackend.h"
#include "../UI/CodeEditorWidget.h"
#include "../Internationalization/LanguageManager.h"
#include "../UI/VisibleTableWidget.h"
#include "../UI/ThemeStatusRole.h"

#include <QApplication>
#include <QClipboard>
#include <QComboBox>
#include <QCoreApplication>
#include <QDateTime>
#include <QFileDialog>
#include <QFormLayout>
#include <QFutureWatcher>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QPromise>
#include <QPushButton>
#include <QSplitter>
#include <QThreadPool>
#include <QTimer>
#include <QVBoxLayout>

#include <Sddl.h>
#include <atomic>
#include <memory>
#include <string>
#include <thread>
#include <utility>

#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Authz.lib")

// 页面、后端和报告按职责拆分，不通过包含源码或 .inc 堆叠实现。
namespace ks::privilege
{
namespace
{
    using namespace access;
    using namespace access::detail;

    // 页面只收集输入、派发采集任务和展示值快照；后台不捕获窗口。
    class AccessPage final : public QWidget
    {
    public:
        explicit AccessPage(QWidget* parent) : QWidget(parent)
        {
            setObjectName(QStringLiteral("privilege_access_page"));
            auto* layout = new QVBoxLayout(this);
            layout->setContentsMargins(8, 8, 8, 8);
            layout->setSpacing(6);
            auto* explanation = new QLabel(text("privilege.workbench.access.intro",
                "选择进程主令牌与对象，分别查看描述符评估、完整性约束和实际句柄打开结果。"), this);
            explanation->setWordWrap(true);
            layout->addWidget(explanation);

            auto* subjectRow = new QHBoxLayout;
            subjectRow->addWidget(new QLabel(text("privilege.workbench.access.pid", "进程 PID"), this));
            m_pid = new QLineEdit(QString::number(GetCurrentProcessId()), this);
            m_pid->setObjectName(QStringLiteral("privilege_access_pid"));
            m_pid->setMaximumWidth(150);
            subjectRow->addWidget(m_pid);
            auto* current = new QPushButton(text("privilege.workbench.access.current", "当前进程"), this);
            subjectRow->addWidget(current);
            subjectRow->addWidget(new QLabel(text("privilege.workbench.access.object_kind", "对象类型"), this));
            m_kind = new QComboBox(this);
            ks::ui::StylePrimaryCombo(m_kind);
            m_kind->setObjectName(QStringLiteral("privilege_access_kind"));
            m_kind->addItem(text("privilege.workbench.access.kind.file", "文件或目录"), int(ObjectKind::File));
            m_kind->addItem(text("privilege.workbench.access.kind.registry", "注册表项"), int(ObjectKind::Registry));
            m_kind->addItem(text("privilege.workbench.access.kind.service", "服务"), int(ObjectKind::Service));
            subjectRow->addWidget(m_kind);
            m_viewLabel = new QLabel(text("privilege.workbench.access.registry_view", "注册表视图"), this);
            m_view = new QComboBox(this);
            ks::ui::StylePrimaryCombo(m_view);
            m_view->setObjectName(QStringLiteral("privilege_access_registry_view"));
            m_view->addItem(QStringLiteral("64-bit"), qulonglong(KEY_WOW64_64KEY));
            m_view->addItem(QStringLiteral("32-bit"), qulonglong(KEY_WOW64_32KEY));
            m_viewLabel->hide();
            m_view->hide();
            subjectRow->addStretch();
            layout->addLayout(subjectRow);
            ks::ui::NormalizeToolbarRow(subjectRow);

            auto* pathRow = new QHBoxLayout;
            pathRow->addWidget(new QLabel(text("privilege.workbench.access.path", "对象名称"), this));
            m_path = new QLineEdit(QCoreApplication::applicationFilePath(), this);
            m_path->setObjectName(QStringLiteral("privilege_access_path"));
            pathRow->addWidget(m_path, 1);
            m_browse = new QPushButton(text("privilege.workbench.access.browse", "选择文件"), this);
            pathRow->addWidget(m_browse);
            layout->addLayout(pathRow);
            ks::ui::NormalizeToolbarRow(pathRow);
            m_pathHint = new QLabel(this);
            m_pathHint->setWordWrap(true);
            layout->addWidget(m_pathHint);
            updateKind();
            auto* viewRow = new QHBoxLayout;
            viewRow->addWidget(m_viewLabel);
            viewRow->addWidget(m_view);
            viewRow->addStretch();
            layout->addLayout(viewRow);
            ks::ui::NormalizeToolbarRow(viewRow);

            auto* accessRow = new QHBoxLayout;
            accessRow->addWidget(new QLabel(text("privilege.workbench.access.operation", "请求权限"), this));
            m_preset = new QComboBox(this);
            // 请求权限预设需有完整选择器底面，不能与只读说明混为一体。
            ks::ui::StylePrimaryCombo(m_preset);
            m_preset->setObjectName(QStringLiteral("privilege_access_preset"));
            m_preset->addItem(text("privilege.workbench.access.preset.read", "读取（通用映射）"), qulonglong(GENERIC_READ));
            m_preset->addItem(text("privilege.workbench.access.preset.write", "写入（只评估）"), qulonglong(GENERIC_WRITE));
            m_preset->addItem(text("privilege.workbench.access.preset.execute", "执行或控制（只评估）"), qulonglong(GENERIC_EXECUTE));
            m_preset->addItem(text("privilege.workbench.access.preset.all", "全部访问（只评估）"), qulonglong(GENERIC_ALL));
            m_preset->addItem(text("privilege.workbench.access.preset.read_control", "读取安全描述符"), qulonglong(READ_CONTROL));
            m_preset->addItem(text("privilege.workbench.access.preset.delete", "删除权（只评估）"), qulonglong(DELETE));
            m_preset->addItem(text("privilege.workbench.access.preset.write_dac", "修改 DACL 权（只评估）"), qulonglong(WRITE_DAC));
            m_preset->addItem(text("privilege.workbench.access.preset.write_owner", "修改所有者权（只评估）"), qulonglong(WRITE_OWNER));
            m_preset->addItem(text("privilege.workbench.access.preset.custom", "自定义掩码"));
            accessRow->addWidget(m_preset);
            m_mask = new QLineEdit(hex(GENERIC_READ), this);
            m_mask->setObjectName(QStringLiteral("privilege_access_mask"));
            m_mask->setMaximumWidth(170);
            accessRow->addWidget(m_mask);
            accessRow->addStretch();
            layout->addLayout(accessRow);
            ks::ui::NormalizeToolbarRow(accessRow);

            auto* actions = new QHBoxLayout;
            m_assess = new QPushButton(text("privilege.workbench.access.assess", "评估描述符"), this);
            m_assess->setObjectName(QStringLiteral("privilege_access_assess"));
            m_probe = new QPushButton(text("privilege.workbench.access.probe", "测试实际打开"), this);
            m_probe->setObjectName(QStringLiteral("privilege_access_probe"));
            m_probe->setEnabled(false);
            m_probe->setToolTip(text("privilege.workbench.access.probe_tooltip",
                "模拟所选主令牌，申请当前权限并立即关闭句柄；不执行写入、删除或服务控制。"));
            m_cancel = new QPushButton(text("privilege.workbench.access.cancel", "取消"), this);
            m_cancel->setEnabled(false);
            actions->addWidget(m_assess);
            actions->addWidget(m_probe);
            actions->addWidget(m_cancel);
            m_status = new QLabel(text("privilege.workbench.access.ready", "等待评估"), this);
            m_status->setWordWrap(true);
            actions->addWidget(m_status, 1);
            layout->addLayout(actions);
            ks::ui::NormalizeToolbarRow(actions);

            auto* split = new QSplitter(Qt::Vertical, this);
            m_table = new ks::ui::VisibleTableWidget(split);
            // 单对象访问诊断 ACE 是评估明细，紧凑复制/导出足够。
            ks::ui::SetTableActionBarMode(m_table, ks::ui::TableActionBarMode::Compact);
            m_table->setObjectName(QStringLiteral("privilege_access_aces"));
            m_table->setColumnCount(8);
            m_table->setHorizontalHeaderLabels({
                text("privilege.workbench.access.column.order", "顺序"),
                text("privilege.workbench.access.column.type", "ACE 类型"), QStringLiteral("SID"),
                text("privilege.workbench.access.column.account", "账户"),
                text("privilege.workbench.access.column.mask", "原始掩码"),
                text("privilege.workbench.access.column.rights", "映射后权限"),
                text("privilege.workbench.access.column.flags", "继承与范围"),
                text("privilege.workbench.access.column.match", "主体匹配与证据")});
            m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
            m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
            m_table->setSelectionMode(QAbstractItemView::ExtendedSelection);
            m_table->setAlternatingRowColors(true);
            m_table->horizontalHeader()->setStretchLastSection(true);
            m_table->setContextMenuPolicy(Qt::CustomContextMenu);
            m_report = new ks::ui::StructuredFieldView(split);
            m_report->setObjectName(QStringLiteral("privilege_access_report"));

            // 标签由原生视图本地化，路径、SID 和 SDDL 保持原始证据值。
            m_report->setDocument(ks::ui::FieldDocument{}.note(QStringLiteral(
                "先评估描述符；实际打开测试需要当前评估快照，输入变化后必须重新评估。")));
            split->setStretchFactor(0, 3);
            split->setStretchFactor(1, 2);
            layout->addWidget(split, 1);

            connect(current, &QPushButton::clicked, this, [this]() { m_pid->setText(QString::number(GetCurrentProcessId())); });
            connect(m_browse, &QPushButton::clicked, this, [this]()
            {
                const QString chosen = QFileDialog::getOpenFileName(this,
                    text("privilege.workbench.access.choose_file", "选择要诊断的文件"), m_path->text());
                if (!chosen.isEmpty()) m_path->setText(chosen);
            });
            connect(m_pid, &QLineEdit::textChanged, this, [this]() { invalidate(); });
            connect(m_path, &QLineEdit::textChanged, this, [this]() { invalidate(); });
            connect(m_mask, &QLineEdit::textChanged, this, [this]() { invalidate(); });
            connect(m_view, &QComboBox::currentIndexChanged, this, [this]() { invalidate(); });
            connect(m_kind, &QComboBox::currentIndexChanged, this, [this]()
            {
                updateKind();
                invalidate();
            });
            connect(m_preset, &QComboBox::currentIndexChanged, this, [this]()
            {
                if (m_preset->currentData().isValid()) m_mask->setText(hex(DWORD(m_preset->currentData().toULongLong())));
                invalidate();
            });
            connect(m_assess, &QPushButton::clicked, this, [this]() { assess(); });
            connect(m_probe, &QPushButton::clicked, this, [this]() { probe(); });
            connect(m_cancel, &QPushButton::clicked, this, [this]()
            {
                invalidate();
                m_status->setText(text("privilege.workbench.access.cancelled", "已取消；后台系统调用返回后释放资源"));
            });
            connect(m_table, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& position)
            {
                const QModelIndex index = m_table->indexAt(position);
                if (!index.isValid()) return;
                auto* item = m_table->item(index.row(), 2);
                if (item == nullptr || item->text().isEmpty()) return;
                const QString sid = item->text();
                QMenu menu(this);
                auto* copy = menu.addAction(text("privilege.workbench.access.copy_sid", "复制 SID"));
                if (menu.exec(m_table->viewport()->mapToGlobal(position)) == copy && QApplication::clipboard() != nullptr)
                    QApplication::clipboard()->setText(sid);
            });
        }

        ~AccessPage() override
        {
            if (m_cancellation != nullptr) m_cancellation->store(true, std::memory_order_relaxed);
        }

    private:
        // 切换对象提示和注册表视图入口。
        void updateKind()
        {
            const auto kind = ObjectKind(m_kind->currentData().toInt());
            m_browse->setEnabled(kind == ObjectKind::File);
            m_view->setVisible(kind == ObjectKind::Registry);
            m_viewLabel->setVisible(kind == ObjectKind::Registry);
            if (kind == ObjectKind::File)
                m_pathHint->setText(text("privilege.workbench.access.hint.file", "输入本地磁盘绝对路径；目录可直接输入。拒绝网络路径、设备路径和命名数据流。"));
            else if (kind == ObjectKind::Registry)
                m_pathHint->setText(text("privilege.workbench.access.hint.registry", "支持 HKLM、HKU 和 HKCU。HKCU 按选定进程用户 SID 解析到 HKU，需已加载该用户配置单元。"));
            else m_pathHint->setText(text("privilege.workbench.access.hint.service", "输入本地服务短名称（例如 Spooler），使用所选服务对象的权限映射。"));
        }

        // 递增代次并取消旧任务，输入变化后不再显示旧快照。
        void invalidate()
        {
            ++m_generation;
            if (m_cancellation != nullptr) m_cancellation->store(true, std::memory_order_relaxed);
            m_result.reset();
            m_assess->setEnabled(true);
            m_probe->setEnabled(false);
            m_cancel->setEnabled(false);
            m_table->setEnabled(false);
            m_table->clearContents();
            m_table->setRowCount(0);
            m_report->setDocument(ks::ui::FieldDocument{}.note(text("privilege.workbench.access.stale_report", "输入已变化；旧评估和打开结果已作废。请重新评估当前主体、对象和请求权限。")));
            m_status->setText(text("privilege.workbench.access.changed", "输入已变化；请重新评估"));
            ks::ui::ApplyStatusRole(m_status, ks::ui::StatusRole::Idle);
        }

        // 验证 PID、路径和访问掩码，输出后台使用的不可变请求。
        bool readRequest(Request& request)
        {
            bool pidValid = false;
            const qulonglong pid = m_pid->text().trimmed().toULongLong(&pidValid, 10);
            bool maskValid = false;
            const QString entered = m_mask->text().trimmed();
            const qulonglong mask = entered.toULongLong(&maskValid,
                entered.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive) ? 16 : 10);
            request.kind = ObjectKind(m_kind->currentData().toInt());
            request.path = m_path->text().trimmed();
            if (!pidValid || pid == 0 || pid > MAXDWORD || !maskValid || mask == 0 || mask > MAXDWORD
                || request.path.isEmpty() || request.path.contains(QChar(0))
                || (request.kind == ObjectKind::Registry && (mask & (KEY_WOW64_32KEY | KEY_WOW64_64KEY)) != 0))
            {
                m_status->setText(text("privilege.workbench.access.validation", "请输入有效 PID、对象名称和非零 32 位掩码；注册表视图使用独立选项。"));
                ks::ui::ApplyStatusRole(m_status, ks::ui::StatusRole::Warning);
                return false;
            }
            request.pid = DWORD(pid);
            request.desired = DWORD(mask);
            request.registryView = DWORD(m_view->currentData().toULongLong());
            return true;
        }

        // 任务与取消标记共同存活，页面销毁自动断开完成回调。
        template<typename Worker>
        void start(Worker worker, const bool probeJob)
        {
            const quint64 generation = ++m_generation;
            m_cancellation = std::make_shared<std::atomic_bool>(false);
            const auto cancellation = m_cancellation;
            m_assess->setEnabled(false);
            m_probe->setEnabled(false);
            m_cancel->setEnabled(true);
            m_table->setEnabled(false);
            m_status->setText(probeJob ? text("privilege.workbench.access.running_probe", "正在核验快照并测试实际打开…")
                : text("privilege.workbench.access.running", "正在后台读取描述符与令牌…"));
            ks::ui::ApplyStatusRole(m_status, ks::ui::StatusRole::Info);
            auto* watcher = new QFutureWatcher<Result>(this);
            auto promise = std::make_shared<QPromise<Result>>();
            promise->start();
            connect(watcher, &QFutureWatcher<Result>::finished, this, [this, watcher, generation]()
            {
                watcher->deleteLater();
                if (generation != m_generation || watcher->future().resultCount() == 0) return;
                const Result result = watcher->result();
                m_assess->setEnabled(true);
                m_cancel->setEnabled(false);
                const bool success = result.stage == Stage::None && result.anchor != nullptr;
                m_result = success ? std::make_shared<Result>(result) : nullptr;
                m_probe->setEnabled(success);
                m_report->setDocument(buildAccessDocument(result));
                m_status->setText(success ? (result.probe
                    ? text("privilege.workbench.access.probe_done", "实际打开测试完成；详见证据报告")
                    : text("privilege.workbench.access.done", "描述符评估完成；实际打开尚未测试"))
                    : text("privilege.workbench.access.failed", "%1失败：%2").arg(stageText(result.stage), errorText(result.error)));
                ks::ui::ApplyStatusRole(m_status, success ? ks::ui::StatusRole::Info : ks::ui::StatusRole::Warning);
                fillTable(result, generation);
            });
            watcher->setFuture(promise->future());
            QThreadPool::globalInstance()->start([promise, worker = std::move(worker), cancellation]() mutable
            {
                Result result;
                try { result = worker(cancellation); }
                catch (...)
                {
                    result.stage = Stage::Internal;
                    result.error = ERROR_UNHANDLED_EXCEPTION;
                }
                promise->addResult(std::move(result));
                promise->finish();
            });
        }

        // 采集当前输入的描述符与主令牌，结果回到页面线程。
        void assess()
        {
            Request request;
            if (!readRequest(request)) return;
            m_result.reset();
            start([request](const auto& cancellation) { return diagnose(request, cancellation); }, false);
        }

        // 使用当前锚点启动一次性模拟线程，不模拟 UI 或共享线程池。
        void probe()
        {
            if (m_result == nullptr || m_result->anchor == nullptr) return;
            const Result baseline = *m_result;
            start([baseline](const auto& cancellation)
            {
                Result result;
                // 只有此一次性线程模拟目标身份；即使恢复失败也随线程退出，
                // 不改变 GUI 线程或共享线程池工作线程的身份。
                std::thread isolated([&]()
                {
                    try { result = probeOnDedicatedThread(baseline, cancellation); }
                    catch (...)
                {
                    result.stage = Stage::Internal;
                    result.error = ERROR_UNHANDLED_EXCEPTION;
                }
                });
                isolated.join();
                return result;
            }, true);
        }

        // 分批写入原始顺序 ACE，代次变化时停止旧结果落表。
        void fillTable(const Result& result, const quint64 generation)
        {
            m_table->clearContents();
            m_table->setRowCount(int(result.aces.size()));
            auto snapshot = std::make_shared<Result>(result);
            auto next = std::make_shared<size_t>(0);
            auto* timer = new QTimer(this);
            timer->setSingleShot(true);
            connect(timer, &QTimer::timeout, this, [this, timer, snapshot, next, generation]()
            {
                if (generation != m_generation)
                {
                    timer->deleteLater();
                    return;
                }
                const size_t end = std::min(*next + size_t(12), snapshot->aces.size());
                for (; *next < end; ++*next)
                {
                    const auto& evidence = snapshot->aces[*next];
                    const QStringList columns{
                        QString::number(*next + 1), aceType(evidence.ace), evidence.sid, evidence.account,
                        hex(evidence.ace.mask), maskText(snapshot->request.kind,
                            mappedAccess(snapshot->request.kind, evidence.ace.mask)),
                        aceFlags(evidence.ace), matchesText(evidence, *snapshot)};
                    for (int column = 0; column < columns.size(); ++column)
                    {
                        auto* item = new QTableWidgetItem(columns[column]);
                        item->setToolTip(columns[column]);
                        m_table->setItem(int(*next), column, item);
                    }
                }
                if (*next < snapshot->aces.size()) timer->start(0);
                else
                {
                    m_table->setEnabled(true);
                    timer->deleteLater();
                }
            });
            timer->start(0);
        }

        QLineEdit* m_pid = nullptr; // 目标 PID 输入。
        QComboBox* m_kind = nullptr; // 对象类别选择。
        QLineEdit* m_path = nullptr; // 对象名称输入。
        QPushButton* m_browse = nullptr; // 文件选择入口。
        QLabel* m_pathHint = nullptr; // 类别对应的路径边界提示。
        QComboBox* m_view = nullptr; // 明确注册表视图选择。
        QLabel* m_viewLabel = nullptr; // 注册表视图标签。
        QComboBox* m_preset = nullptr; // 常用访问请求预设。
        QLineEdit* m_mask = nullptr; // 用户输入的访问掩码。
        QPushButton* m_assess = nullptr; // 描述符采集入口。
        QPushButton* m_probe = nullptr; // 锚点一致时启用的实际打开入口。
        QPushButton* m_cancel = nullptr; // 当前后台任务取消入口。
        QLabel* m_status = nullptr; // 本轮查询状态。
        ks::ui::VisibleTableWidget* m_table = nullptr; // 按原始顺序分批展示的 ACE 表。
        ks::ui::StructuredFieldView* m_report = nullptr; // 内置只读原文报告编辑器。
        quint64 m_generation = 0; // 输入及任务代次，用于丢弃旧回执。
        std::shared_ptr<std::atomic_bool> m_cancellation; // 后台共用的可取消标记。
        std::shared_ptr<Result> m_result; // 当前仍可复核的诊断证据锚点。
    };
}

    QWidget* createAccessDiagnosticPage(QWidget* parent)
    {
        return new AccessPage(parent);
    }
}
