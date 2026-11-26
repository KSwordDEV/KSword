#pragma once

#include "NativeStopMemoryCandidates.h"
#include <QWidget>
#include <functional>

class QLabel;
class QLineEdit;
class QPushButton;
class QSpinBox;
class QStandardItemModel;
class QTableView;
namespace ks::ui { class StructuredFieldView; }

namespace ks::action_analyze
{
    // 导航：行为分析→原写入/执行页→ParameterWorkspace参数正文；此Pane不创建worker或owner。
    // 用户流程：原绑定→显式截止段读取→选原调用→明确子范围→准备草稿→原AddRange按钮。
    class PrivateExecutionCandidatesPane final : public QWidget
    {
    public:
        // parent为原ParameterWorkspace正文；只组合共享参数分区、表格与折叠字段视图。
        explicit PrivateExecutionCandidatesPane(QWidget* parent);
        // context来自原worker本轮快照；workerBusy来自原单在途动作，不查询进程或项目。
        void SetContext(const NativeExecutionCandidatesContext& context, bool workerBusy = false);
        // GUI线程冻结完整只读请求；nextPage只使用已显示页的原游标/快照，成功才替换out。
        bool PrepareRead(NativeExecutionCandidatesRequest& out, bool nextPage = false);
        // 原worker结果回到GUI后调用；只接纳本轮、本次请求的不可变回执，失败保留旧页。
        void Consume(const std::shared_ptr<const NativeExecutionCandidatesResult>& view);
        // 原页面未能排入队列时调用；仅撤销匹配请求的等待态，不取消任何后台工作。
        void ReadNotQueued(std::uint64_t serial);
        // 按当前唯一选中原调用及明确输入准备纯值范围；成功才替换out，不提交AddRange。
        bool PrepareSelectedDraft(Ksword::ActionAnalyze::Detection::PrivateExecutionRangeDraft& out);

        std::function<void(const NativeExecutionCandidatesRequest&)> requestRead; // 宿主接原worker/new action。
        std::function<void(const Ksword::ActionAnalyze::Detection::PrivateExecutionRangeDraft&, const QString&)> draftReady; // 冻结草稿及来源，宿主仅SetDraft。

    protected:
        // 语言/字体变化仅更新当前有界投影与高度，保留结果、选择和草稿，不触发读取。
        void changeEvent(QEvent* event) override;

    private:
        // 构造共享布局及连接；不重复创建ParameterWorkspace或参数滚动区。
        void BuildLayout();
        // 根据纯值状态更新短提示、动作资格和结果来源，不重新读取或清空编辑草稿。
        void Render();
        // 只在新页/语言变化时投影最多8行；keepSelection只用于同页语言变化。
        void RenderRows(bool keepSelection = false);
        // 鼠标/键盘选择都沿同一路径更新规范字段；不改写范围输入，不回调宿主。
        void SelectionChanged();
        // 显式将可用整段草稿填入输入；不具备整段资格时不自动裁剪或对齐。
        void LoadSelectedRange();
        // 范围编辑时记录当时所选原调用和页身份，防止切行后沿用别行旧草稿。
        void BindEditedDraft();
        // 执行按钮的纯值准备并交回宿主；没有回调时保持可见错误，不标成已执行。
        void DispatchRead(bool nextPage);
        void DispatchDraft();
        // 返回唯一选中行号或-1；不依赖currentIndex充当选中状态。
        int SelectedRow() const;
        // 检查已显示页与本轮目录/sample/目标及原回执项目ID一致，不授予现场控制权。
        bool CurrentPage() const;
        // 同一scope、完整snapshot和原坐标才允许继续使用旧输入；仅重读同一页不丢弃草稿。
        bool DraftMatchesSelection() const;

        NativeExecutionCandidatesContext m_context; // 最新本轮绑定，不覆盖旧页自己的来源。
        std::optional<NativeExecutionCandidatesRequest> m_pending; // 当前单在途请求的完整冻结值。
        std::shared_ptr<const NativeExecutionCandidatesResult> m_attempt; // 最近已接纳回执，失败也保留。
        std::shared_ptr<const NativeExecutionCandidatesResult> m_shown; // 最近成功页，失败不擦除。
        std::shared_ptr<const NativeExecutionCandidatesResult> m_draftPage; // 当前输入最初编辑时的真实页。
        std::optional<Ksword::ActionAnalyze::Detection::RawLocator> m_draftOrigin; // 当前输入对应原调用坐标。
        std::uint64_t m_serial = 0; // 单调请求号，换绑定不重置，旧回执不能碰撞。
        bool m_workerBusy = false; // 宿主共享worker是否正在执行其它动作。
        QString m_notice; // 原位反馈的翻译源；不当成候选读取成功状态。

        QSpinBox* m_through = nullptr; // 待读截止段，修改不自动查询或改写旧结果。
        QPushButton* m_read = nullptr; // 显式读取/重读首个候选页。
        QPushButton* m_next = nullptr; // 显式请求同前缀下一页，可原位重试失败翻页。
        QLabel* m_status = nullptr; // 未读/读取中/失败/空结果/有结果分别呈现。
        QLabel* m_source = nullptr; // 旧结果真实项目、采样、截止段及读取完成时间。
        QTableView* m_table = nullptr; // 有界候选列表，表格操作条None，保留真实原行索引。
        QStandardItemModel* m_model = nullptr; // 最多8×3个只读单元格，不缓存原始API包。
        QLineEdit* m_address = nullptr; // 用户明确子范围起点，支持十进制或0x。
        QLineEdit* m_pages = nullptr; // 明确正十进制uint64页数，不自动外扩原实际范围。
        QPushButton* m_load = nullptr; // 显式填入候选可用整段；选择本身不覆盖输入。
        QPushButton* m_prepare = nullptr; // 只生成草稿供原范围Pane接收。
        QLabel* m_draftSource = nullptr; // 输入归属的原调用坐标，切行时仍保留旧草稿身份。
        QLabel* m_eligibility = nullptr; // 说明本轮NX/完整Held、身份和范围依赖。
        ks::ui::StructuredFieldView* m_fields = nullptr; // 单一规范字段源，折叠显示并保留复制/导出。
    };
}
