#include "../Framework.h"
#include "PrivateExecutionCandidatesPane.h"
#include "PrivateExecutionCandidatesFields.h"
#include "../UI/StructuredFieldView.h"
#include "../Internationalization/LanguageManager.h"

#include <QEvent>
#include <QItemSelectionModel>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QSignalBlocker>
#include <QSpinBox>
#include <QTableView>
#include <charconv>
#include <limits>

namespace ks::action_analyze
{
    namespace detection = Ksword::ActionAnalyze::Detection;
    using ks::i18n::sourceText;

    // 输入原ParameterWorkspace正文；连接全部纯UI动作，不创建worker、计时器或owner。
    PrivateExecutionCandidatesPane::PrivateExecutionCandidatesPane(QWidget* parent) : QWidget(parent)
    {
        BuildLayout();
        connect(m_read, &QPushButton::clicked, this, [this] { DispatchRead(false); });
        connect(m_next, &QPushButton::clicked, this, [this] { DispatchRead(true); });
        connect(m_load, &QPushButton::clicked, this, [this] { LoadSelectedRange(); });
        connect(m_prepare, &QPushButton::clicked, this, [this] { DispatchDraft(); });
        connect(m_table->selectionModel(), &QItemSelectionModel::selectionChanged,
            this, [this] { SelectionChanged(); });
        connect(m_address, &QLineEdit::textEdited, this, [this] { BindEditedDraft(); });
        connect(m_pages, &QSpinBox::valueChanged, this, [this] { BindEditedDraft(); });
        connect(m_through, &QSpinBox::valueChanged, this, [this] { Render(); });
        RenderRows();
        Render();
    }

    // context来自原session已发布的快照；只有换轮才撤销等待态，旧页和旧草稿仍保留来源。
    void PrivateExecutionCandidatesPane::SetContext(const NativeExecutionCandidatesContext& context, bool workerBusy)
    {
        if (!SameExecutionCandidatesBinding(m_context, context))
        {
            m_pending.reset(); // 旧worker返回仍有serial，但不能覆盖新轮请求或成为可用范围。
            m_notice.clear();
        }
        m_context = context;
        m_workerBusy = workerBusy;
        Render();
    }

    // GUI线程只冻结完整拥有值；after/snapshot来自旧页自身，绝不来自新截止段输入。
    bool PrivateExecutionCandidatesPane::PrepareRead(NativeExecutionCandidatesRequest& out, bool nextPage)
    {
        if (m_workerBusy || m_pending || !SameExecutionCandidatesBinding(m_context, m_context) ||
            m_serial == (std::numeric_limits<std::uint64_t>::max)())
        {
            m_notice = QStringLiteral("需有本轮原项目、采样和目标强实例，且原工作线程空闲。");
            Render();
            return false;
        }
        NativeExecutionCandidatesRequest request; // 入队后即使用户改截止段也不修改请求。
        request.context = m_context;
        request.serial = ++m_serial;
        request.throughOrdinal = static_cast<std::uint64_t>(m_through->value());
        if (nextPage)
        {
            if (!CurrentPage() || !m_shown->page->nextAfter)
            {
                m_notice = QStringLiteral("当前结果无可续读页；请显式重新读取候选。");
                Render();
                return false;
            }
            request.throughOrdinal = m_shown->page->throughOrdinal;
            request.after = m_shown->page->nextAfter;
            request.snapshot = m_shown->page->snapshot;
        }
        m_pending = request;
        out = request; // 只有全部准备通过才替换输出，宿主仍需原worker排队资格。
        m_notice.clear();
        Render();
        return true;
    }

    // 输入原worker完整回执；serial和绑定都匹配后才结束等待，不接纳其它轮/其它动作结果。
    void PrivateExecutionCandidatesPane::Consume(const std::shared_ptr<const NativeExecutionCandidatesResult>& view)
    {
        if (!view || !m_pending || view->request.serial != m_pending->serial ||
            !SameExecutionCandidatesBinding(view->request.context, m_pending->context) ||
            !SameExecutionCandidatesBinding(view->request.context, m_context) ||
            view->request.throughOrdinal != m_pending->throughOrdinal || view->request.after != m_pending->after ||
            view->request.snapshot != m_pending->snapshot)
        {
            return; // 旧回执不清空新请求，不改写旧结果身份和用户输入。
        }
        m_pending.reset();
        m_attempt = view;
        m_notice.clear();
        if (view->result && view->page && SameExecutionCandidatesBinding(view->context, m_context) &&
            view->page->scope.projectId == view->context.projectId &&
            view->page->scope.sampleId == view->context.sampleId &&
            view->page->throughOrdinal == view->request.throughOrdinal &&
            view->page->rows.size() <= detection::kPrivateCandidateMaxPage)
        {
            m_shown = view; // 只有真正成功才换表，失败保留旧页并明确显示最近失败。
            RenderRows();
        }
        else if (view->result)
        {
            m_notice = QStringLiteral("候选回执归属不匹配；保留旧结果并重新读取。");
        }
        SelectionChanged();
    }

    // 宿主排队失败后撤销此serial等待；没有取消调用，不触碰任何原生任务状态。
    void PrivateExecutionCandidatesPane::ReadNotQueued(std::uint64_t serial)
    {
        if (m_pending && m_pending->serial == serial)
        {
            m_pending.reset();
            m_notice = QStringLiteral("候选读取未排入原工作线程；可原位重试。");
            Render();
        }
    }

    // 输出选中行号；SingleSelection也检查selectedRows，不能用残留currentIndex作为用户选择。
    int PrivateExecutionCandidatesPane::SelectedRow() const
    {
        const auto rows = m_table->selectionModel()->selectedRows(); // 当前显式整行选区。
        return rows.size() == 1 ? rows.front().row() : -1;
    }

    // 当前page的scope是唯一结果归属；当前编辑的截止段不参与旧页身份校验。
    bool PrivateExecutionCandidatesPane::CurrentPage() const
    {
        return m_shown && m_shown->result && m_shown->page &&
            SameExecutionCandidatesBinding(m_context, m_shown->context) &&
            m_shown->page->scope.projectId == m_shown->context.projectId &&
            m_shown->page->scope.sampleId == m_shown->context.sampleId;
    }

    // 比较输入当时的真实页与当前选中行；跨页、跨scope或快照变化不能继承草稿身份。
    bool PrivateExecutionCandidatesPane::DraftMatchesSelection() const
    {
        const auto selected = SelectedRow(); // 仅当前唯一选中原调用可成为范围准备来源。
        return CurrentPage() && m_draftPage && m_draftPage->page && m_draftOrigin && selected >= 0 &&
            static_cast<std::size_t>(selected) < m_shown->page->rows.size() &&
            SameExecutionCandidatesBinding(m_draftPage->context, m_shown->context) &&
            m_draftPage->page->scope.projectId == m_shown->page->scope.projectId &&
            m_draftPage->page->scope.sampleId == m_shown->page->scope.sampleId &&
            m_draftPage->page->snapshot == m_shown->page->snapshot &&
            m_draftPage->page->throughOrdinal == m_shown->page->throughOrdinal &&
            m_draftOrigin == m_shown->page->rows[static_cast<std::size_t>(selected)].origin.evidence.raw;
    }

    // 用户编辑或显式填入时才绑定输入来源；选行和刷新均不静默改变草稿归属。
    void PrivateExecutionCandidatesPane::BindEditedDraft()
    {
        const auto selected = SelectedRow(); // 此次编辑时的明确原调用。
        m_draftPage.reset();
        m_draftOrigin.reset();
        if (CurrentPage() && selected >= 0 && static_cast<std::size_t>(selected) < m_shown->page->rows.size())
        {
            m_draftPage = m_shown;
            m_draftOrigin = m_shown->page->rows[static_cast<std::size_t>(selected)].origin.evidence.raw;
        }
        m_notice.clear();
        Render();
    }

    // 只在用户点击后填可用整段；手工草稿已有内容时保留，用户可自行编辑明确子范围。
    void PrivateExecutionCandidatesPane::LoadSelectedRange()
    {
        const auto selected = SelectedRow(); // 点击冻结的唯一选中行。
        if (!CurrentPage() || selected < 0 || static_cast<std::size_t>(selected) >= m_shown->page->rows.size())
        {
            return;
        }
        const auto& row = m_shown->page->rows[static_cast<std::size_t>(selected)]; // 当前页原调用。
        if (!row.wholeRangeDraft || !m_address->text().trimmed().isEmpty())
        {
            m_notice = QStringLiteral("整段不可用或已有子范围草稿；请保留并手工编辑明确范围。");
            Render();
            return;
        }
        const QSignalBlocker blocked(m_pages); // 程序式填值只绑定一次来源，不冒充用户逐步编辑。
        m_address->setText(QStringLiteral("0x%1").arg(QString::number(row.wholeRangeDraft->address, 16)));
        m_pages->setValue(static_cast<int>(row.wholeRangeDraft->bytes / 4096));
        BindEditedDraft();
    }

    // 输出冻结范围草稿；NX/Held仅作UI资格，真正AddRange仍由原owner重新核验。
    bool PrivateExecutionCandidatesPane::PrepareSelectedDraft(detection::PrivateExecutionRangeDraft& out)
    {
        const auto selected = SelectedRow(); // 点击时选中原行；新截止段输入不会改变它的scope。
        if (!CurrentPage() || m_workerBusy || m_pending || !m_context.nxBinding || !m_context.fullHeld ||
            !m_context.target.attached || selected < 0 ||
            static_cast<std::size_t>(selected) >= m_shown->page->rows.size() || !DraftMatchesSelection() ||
            m_attempt != m_shown)
        {
            m_notice = QStringLiteral("需本轮 NX 完整 Held、匹配的候选页和已绑定原调用的子范围草稿。");
            Render();
            return false;
        }
        const auto& row = m_shown->page->rows[static_cast<std::size_t>(selected)]; // 当前成功页唯一原调用。
        const auto& scope = m_shown->page->scope; // 用结果自己的scope，不用UI新输入冒充旧结果。
        if (!row.origin.record.apiMemoryLifecycle || row.origin.evidence.raw != m_draftOrigin ||
            row.origin.evidence.projectId != scope.projectId || row.origin.evidence.sampleId != scope.sampleId)
        {
            m_notice = QStringLiteral("子范围草稿与选中原调用不匹配；请重新明确编辑范围。");
            Render();
            return false;
        }
        const auto& fields = *row.origin.record.apiMemoryLifecycle; // 目标只取原AAIM1强实例，不回填PID。
        if (!row.strongTarget || fields.targetPid != m_context.target.pid ||
            fields.targetCreationFileTime != m_context.target.creationFileTime)
        {
            m_notice = QStringLiteral("选中候选的目标 PID 与创建 FILETIME 必须匹配本轮原调试目标。");
            Render();
            return false;
        }
        const auto text = m_address->text().trimmed().toLatin1(); // 全字符无损解析地址，不隐式向下对齐。
        const bool hex = text.startsWith("0x") || text.startsWith("0X");
        const auto offset = hex ? 2 : 0; // 十六进制前缀长度，裸十进制不跳过字符。
        std::uint64_t address = 0; // 成功解析后才交共享范围门禁。
        const auto parsed = std::from_chars(text.data() + offset, text.data() + text.size(), address, hex ? 16 : 10);
        detection::PrivateExecutionRangeDraft draft; // 输出完整原调用，不剥离历史来源和实际范围。
        if (text.isEmpty() || parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size() ||
            !detection::PreparePrivateExecutionRangeDraft(row, address,
                static_cast<std::uint64_t>(m_pages->value()) * 4096, draft))
        {
            m_notice = QStringLiteral("请输入实际输出范围内部的 4KiB 对齐子范围，长度为 1–64 页；不自动扩大或裁剪。");
            Render();
            return false;
        }
        out = std::move(draft);
        m_notice.clear();
        Render();
        return true;
    }

    // 仅派发已冻结的值请求；回调最后执行，宿主可能在同步回调中销毁此Pane。
    void PrivateExecutionCandidatesPane::DispatchRead(bool nextPage)
    {
        const auto callback = requestRead; // 复制回调，不在宿主操作后访问this。
        if (!callback)
        {
            m_notice = QStringLiteral("候选读取入口尚未接入原工作线程。");
            Render();
            return;
        }
        NativeExecutionCandidatesRequest request; // 只有准备成功才能入原worker。
        if (PrepareRead(request, nextPage))
        {
            callback(request);
        }
    }

    // 输出冻结draft及来源说明；宿主SetDraft可模态确认，前后身份复核由宿主负责。
    void PrivateExecutionCandidatesPane::DispatchDraft()
    {
        const auto callback = draftReady; // 同步回调可以打开确认框/销毁页面，调用后不再访问this。
        if (!callback)
        {
            m_notice = QStringLiteral("范围草稿入口尚未接入原范围区。");
            Render();
            return;
        }
        detection::PrivateExecutionRangeDraft draft; // 点击冻结的完整纯值范围。
        if (!PrepareSelectedDraft(draft))
        {
            return;
        }
        const auto origin = sourceText(QStringLiteral("候选来源：项目 %1 / 采样 %2 / 原段 %3 / 记录 %4 / SHA-256 %5；Free 实际释放与分配代次未知。"))
            .arg(QString::fromStdString(draft.projectId), QString::fromStdString(draft.sampleId))
            .arg(draft.origin.record.segmentOrdinal).arg(draft.origin.record.recordSequence)
            .arg(QString::fromStdString(draft.origin.sha256)); // 来源来自draft自身，不使用新参数。
        m_notice = QStringLiteral("已准备范围草稿；请在原范围区确认后使用显式追加按钮。");
        Render();
        callback(draft, origin);
    }
}
