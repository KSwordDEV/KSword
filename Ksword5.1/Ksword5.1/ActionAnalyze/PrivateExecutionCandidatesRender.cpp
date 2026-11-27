#include "../Framework.h"
#include "PrivateExecutionCandidatesPane.h"
#include "PrivateExecutionCandidatesFields.h"
#include "../Internationalization/LanguageManager.h"
#include "../UI/StructuredFieldView.h"

#include <QDateTime>
#include <QTimeZone>
#include <QEvent>
#include <QHeaderView>
#include <QItemSelectionModel>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QSignalBlocker>
#include <QSpinBox>
#include <QStandardItemModel>
#include <QTableView>
#include <algorithm>

namespace ks::action_analyze
{
    using ks::i18n::sourceText;

    // 输入原成功页，投影最多8行只读单元格；语言变化时保留同页原选择，读取不排序。
    void PrivateExecutionCandidatesPane::RenderRows(bool keepSelection)
    {
        const auto selected = keepSelection ? SelectedRow() : -1; // 仅同页语言变化保留行索引。
        const QSignalBlocker blocked(m_table->selectionModel()); // 重建期间不发布半成品选择/草稿来源。
        m_model->removeRows(0, m_model->rowCount());
        m_model->setHorizontalHeaderLabels({sourceText(QStringLiteral("原调用 / 段:记录")),
            sourceText(QStringLiteral("实际输出范围")), sourceText(QStringLiteral("候选状态 / Free"))});
        m_read->setAccessibleName(sourceText(QStringLiteral("读取候选"))); // 纯图标动作的名称也随语言更新。
        if (m_shown && m_shown->page)
        {
            for (const auto& row : m_shown->page->rows) // 每页有界，不遍历全部归档或查询当前进程。
            {
                const auto& record = row.origin.record; // 每行保留核心原序，表头禁止重排业务排序。
                const auto call = QStringLiteral("%1\n%2:%3").arg(QString::fromStdString(record.operation))
                    .arg(record.segmentOrdinal).arg(record.recordSequence);
                const QStringList values{call, PrivateCandidateRange(row), PrivateCandidateState(row)};
                QList<QStandardItem*> items; // 最多三个单元格，归档数据不进入可编辑角色。
                for (const auto& value : values)
                {
                    auto* item = new QStandardItem(value); // 模型拥有item；tooltip保留被截断的完整文本。
                    item->setEditable(false);
                    item->setToolTip(value);
                    items.push_back(item);
                }
                m_model->appendRow(items);
            }
        }

        // 内部只滚动候选表，父ParameterWorkspace继续承担参数正文滚动；不新套滚动壳。
        const auto line = m_table->fontMetrics().height(); // 真实字体高度，缩放后保留两行原调用坐标。
        const auto rowHeight = (std::max)(40, line * 2 + 12);
        m_table->verticalHeader()->setDefaultSectionSize(rowHeight);
        m_table->setFixedHeight(rowHeight * 4 + m_table->horizontalHeader()->sizeHint().height() + 8);
        m_fields->setFixedHeight((std::max)(220, line * 10 + 60)); // 大字段只在共享折叠分区中按需显示。
        if (selected >= 0 && selected < m_model->rowCount())
        {
            m_table->selectRow(selected);
        }
    }

    // 鼠标/键盘选择都只更新单一字段文档，不执行读档、填参或AddRange。
    void PrivateExecutionCandidatesPane::SelectionChanged()
    {
        ks::ui::FieldDocument document; // 单一来源文档，旧页与最新失败分别保留身份。
        if (m_shown)
        {
            document = PrivateExecutionCandidatesFields(*m_shown, SelectedRow());
        }
        else if (m_attempt)
        {
            document = PrivateExecutionCandidatesFields(*m_attempt, -1);
        }
        if (m_attempt && m_shown && m_attempt != m_shown)
        {
            document.section(QStringLiteral("最近候选读取失败"));
            document.field(QStringLiteral("项目目录"), QString::fromStdWString(m_attempt->context.projectDirectory));
            document.field(QStringLiteral("采样 ID"), QString::fromStdString(m_attempt->context.sampleId));
            document.field(QStringLiteral("候选截止段"), QString::number(m_attempt->request.throughOrdinal));
            document.field(QStringLiteral("阶段"), QString::fromLatin1(m_attempt->result.detail));
            document.field(QStringLiteral("状态"), QString::fromLatin1(Ksword::ActionAnalyze::ProjectErrorName(m_attempt->result.error)));
            document.field(QStringLiteral("Win32 错误"), QString::number(m_attempt->result.nativeError));
        }
        m_fields->setDocument(document);
        Render();
    }

    // 仅使用已冻结结果/本轮资格更新提示；用户更改截止段不改写结果来源或清空范围输入。
    void PrivateExecutionCandidatesPane::Render()
    {
        const bool bound = SameExecutionCandidatesBinding(m_context, m_context); // 目录/sample/目标强实例完整。
        const bool current = CurrentPage(); // 旧页仍可读，但未匹配本轮时不能准备或翻页。
        const bool idle = !m_workerBusy && !m_pending;
        m_read->setEnabled(bound && idle);
        m_next->setEnabled(current && idle && m_shown->page->nextAfter.has_value());

        QString status = sourceText(QStringLiteral("尚未读取候选；请选择截止段并显式读取。")); // 初始态不画成空结果。
        if (m_pending)
        {
            status = sourceText(QStringLiteral("正在读取已提交前缀 1–%1；保留原结果和草稿。"))
                .arg(m_pending->throughOrdinal);
        }
        else if (m_attempt && (!m_attempt->result || m_attempt != m_shown))
        {
            status = sourceText(QStringLiteral("候选读取失败：%1 / %2 / Win32 %3。保留旧结果，请重读或重试翻页。"))
                .arg(QString::fromLatin1(Ksword::ActionAnalyze::ProjectErrorName(m_attempt->result.error)),
                    QString::fromLatin1(m_attempt->result.detail)).arg(m_attempt->result.nativeError);
        }
        else if (m_shown && m_shown->page)
        {
            const auto& page = *m_shown->page; // 此处所有计数都是旧结果自己的已核验前缀。
            status = sourceText(QStringLiteral("本页 %1 行；前缀范围候选 %2，Free 请求 %3，损坏 AAIM1 %4，旧格式 %5。"))
                .arg(page.rows.size()).arg(page.rangeCandidateCount).arg(page.freeRequestCount)
                .arg(page.malformedLifecycleCount).arg(page.legacyLifecycleCount);
            if (page.rows.empty())
            {
                status += QLatin1Char('\n') + sourceText(QStringLiteral("读取成功，当前页没有合法 AAIM1 调用；缺口计数仍按原前缀保留。"));
            }
        }
        if (!m_notice.isEmpty())
        {
            status += QLatin1Char('\n') + sourceText(m_notice);
        }
        m_status->setText(status);

        if (m_shown && m_shown->page)
        {
            const auto& page = *m_shown->page; // 不把新截止段值贴到旧页的来源说明上。
            constexpr std::uint64_t epoch = 116444736000000000ULL; // FILETIME到Unix毫秒的固定纪元差。
            const auto completed = m_shown->readFileTime >= epoch ?
                QDateTime::fromMSecsSinceEpoch(static_cast<qint64>((m_shown->readFileTime - epoch) / 10000), QTimeZone::utc())
                    .toString(Qt::ISODateWithMs) : sourceText(QStringLiteral("未知"));
            auto source = sourceText(QStringLiteral("结果来源：%1\n项目 %2 / 采样 %3 / 截止段 %4 / 读取完成 %5"))
                .arg(QString::fromStdWString(m_shown->context.projectDirectory), QString::fromStdString(page.scope.projectId),
                    QString::fromStdString(page.scope.sampleId)).arg(page.throughOrdinal).arg(completed);
            if (!current)
            {
                source += QLatin1Char('\n') + sourceText(QStringLiteral("旧结果与本轮绑定不同，仅供查看。"));
            }
            if (static_cast<std::uint64_t>(m_through->value()) != page.throughOrdinal)
            {
                source += QLatin1Char('\n') + sourceText(QStringLiteral("截止段草稿已改变；已显示结果与下一页仍属于原截止段。"));
            }
            m_source->setText(source);
        }
        else
        {
            m_source->setText(sourceText(QStringLiteral("待读来源：%1 / 采样 %2"))
                .arg(QString::fromStdWString(m_context.projectDirectory), QString::fromStdString(m_context.sampleId)));
        }

        const auto selected = SelectedRow(); // 唯一选区索引，所有现场准备资格均独立于数据可读性。
        const auto* row = current && selected >= 0 && static_cast<std::size_t>(selected) < m_shown->page->rows.size() ?
            &m_shown->page->rows[static_cast<std::size_t>(selected)] : nullptr;
        const auto* fields = row && row->origin.record.apiMemoryLifecycle ? &*row->origin.record.apiMemoryLifecycle : nullptr;
        const bool rangeOperation = fields && (fields->operation == Ksword::Evidence::ApiMemoryOperation::Allocate ||
            fields->operation == Ksword::Evidence::ApiMemoryOperation::Protect); // 只有分配/保护具有实际输出范围。
        const bool target = fields && row->strongTarget && fields->targetPid == m_context.target.pid &&
            fields->targetCreationFileTime == m_context.target.creationFileTime;
        const bool eligible = idle && current && m_attempt == m_shown && target && rangeOperation && row->rangeCandidate &&
            m_context.nxBinding && m_context.fullHeld && m_context.target.attached;
        m_load->setEnabled(eligible && row->wholeRangeDraft.has_value());
        m_prepare->setEnabled(eligible && DraftMatchesSelection());

        auto eligibility = sourceText(QStringLiteral("本轮目标 PID %1 / 创建 FILETIME %2。准备草稿要求本轮 NX 完整 Held、相同目标强实例及实际输出内的整页范围；Free 实际释放和分配代次未知。"))
            .arg(m_context.target.pid).arg(m_context.target.creationFileTime); // 描述当前目标和明确动作前提。
        eligibility += QLatin1Char('\n') + sourceText(QStringLiteral("当前 NX：%1；完整 Held：%2；目标已附加：%3。"))
            .arg(sourceText(m_context.nxBinding ? QStringLiteral("是") : QStringLiteral("否")),
                sourceText(m_context.fullHeld ? QStringLiteral("是") : QStringLiteral("否")),
                sourceText(m_context.target.attached ? QStringLiteral("是") : QStringLiteral("否")));
        if (row && !target)
        {
            eligibility += QLatin1Char('\n') + sourceText(QStringLiteral("选中候选的目标 PID 与创建 FILETIME 必须匹配本轮原调试目标。"));
        }
        if (fields && fields->operation == Ksword::Evidence::ApiMemoryOperation::Unmap)
        {
            eligibility += QLatin1Char('\n') + sourceText(QStringLiteral("解除映射请求没有实际输出范围，不能准备私有 NX 范围草稿。"));
        }
        m_eligibility->setText(eligibility);
        if (m_draftPage && m_draftOrigin)
        {
            m_draftSource->setText(sourceText(QStringLiteral("子范围草稿来源：采样 %1 / 原段 %2 / 记录 %3；切换选择不会改写此来源。"))
                .arg(QString::fromStdString(m_draftPage->page->scope.sampleId))
                .arg(m_draftOrigin->segmentOrdinal).arg(m_draftOrigin->sequence));
        }
        else
        {
            m_draftSource->setText(sourceText(QStringLiteral("尚未绑定子范围草稿；选中原调用后明确填写或填入整段。")));
        }
    }

    // 字体/语言改变只处理最多8行及当前文档；不创建新读取，也不改变用户子范围输入。
    void PrivateExecutionCandidatesPane::changeEvent(QEvent* event)
    {
        QWidget::changeEvent(event);
        if (m_model && m_fields && (event->type() == QEvent::LanguageChange || event->type() == QEvent::FontChange))
        {
            RenderRows(true);
            SelectionChanged();
        }
    }
}
