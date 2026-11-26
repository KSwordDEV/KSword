#pragma once

#include "../../../KswordCLI/ActionAnalyze/Project/ProjectDocument.h"
#include <QPersistentModelIndex>
#include <QWidget>
#include <functional>

class QCheckBox;
class QComboBox;
class QEvent;
class QGroupBox;
class QLabel;
class QLineEdit;
class QPushButton;
class QTableView;

namespace ks::ui
{
    class AsyncOperation;
    class ParameterWorkspace;
}

namespace ks::action_analyze
{
    class BreakpointDraftModel;
    struct ProjectSnapshot;

    // 在行为分析工作台内编辑并保存项目的离线断点定义。
    class ActionAnalyzeBreakpointPage final : public QWidget
    {
    public:
        // 自动创建参数区、固定动作区及草稿表。parent 为工作台的页签宿主。
        explicit ActionAnalyzeBreakpointPage(QWidget* parent = nullptr);
        ~ActionAnalyzeBreakpointPage() override;

        // 工作台在异步打开/刷新成功后交付已核验快照，本页据此载入定义。
        void setProjectContext(const ProjectSnapshot& snapshot);
        std::function<void(const QString&, const QString&)> projectDefinitionsSaved; // 已保存的清单路径和项目 UUID。
        // 工作台连接原控制页：输入模块路径、RVA及定义ID，返回草稿是否被接收，不表示已设断点。
        void setLivePreparation(std::function<bool(const QString&, std::uint32_t, const QString&, const QString&)> prepare);

    protected:
        // 跟随 Qt 语言切换更新文案，保留当前编辑内容和表格选区。
        void changeEvent(QEvent* event) override;

    private:
        // 表单/列表动作的最后回执。表单编辑后清理旧回执，避免表示仍已校验。
        enum class Feedback
        {
            None, InvalidModule, InvalidRva, InvalidSymbol, Duplicate, Limit, PendingEdit, Added, Updated, Removed
        };

        // 仅保留定义编辑所需的项目身份及基准，不复制工作台的采样目录。
        struct ProjectContext
        {
            QString manifestPath; // 经工作台验证的清单路径。
            QString id; // 项目 UUID，和路径共同识别项目。
            QString title; // 当前项目标题，用于区分保存目标。
            QString revisionId; // 期望写入的基准修订。
            quint64 generation = 0; // 丢弃在保存完成前发起的旧读结果。
            std::vector<Ksword::ActionAnalyze::BreakpointDefinition> definitions; // 项目中已提交的定义。
            bool matches(const ProjectContext& other) const; // 同项目、同清单才返回 true。
        };

        void createForm();       // 构造滚动参数区和固定表单动作，由构造函数调用。
        void createList();       // 构造草稿表、共享宿主和列表动作，由构造函数调用。
        void retranslate();      // 更新固定文本、表头和业务状态，无需重建控件。
        void updateControls();   // 根据选区、编辑对象及最近回执更新状态和可用性。
        void updateProjectControls(); // 显示实际项目、存储回执及切换资格。
        void acceptProject(ProjectContext project); // 比对新读回的项目，按草稿状态决定是否载入。
        void loadProject(ProjectContext project); // 用确认可用的已提交定义替换表格及基准。
        void openPendingProject(); // 显式载入待切换项目，必要时确认放弃未保存改动。
        void saveProject(); // 冻结项目身份及草稿，通过共享异步事务保存。
        void reportSaveFailure(Ksword::ActionAnalyze::ProjectError error); // 保留草稿并处理已到达的目录回读。
        bool hasDraftChanges() const; // 对比草稿表与同一项目的已提交基准。
        bool hasFormChanges() const; // 比较当前表单与其开始编辑时的值，供切换保护使用。
        void formChanged();      // 输入改变时清理旧回执，并按新定位方式更新文案。
        void clearForm();        // 恢复新增表单，保留已收录草稿和表格选区。
        void editSelection();    // 明确载入所选草稿，表单有改动时保留原编辑对象。
        void removeSelection();  // 删除所选草稿，保留独立表单和其它草稿。
        void prepareLiveSelection(); // 冻结所选RVA定义、选择模块并送入原控制页，不创建新owner。
        void commitForm();       // 校验并提交表单，失败时保持模型和当前输入。
        void reportError(Feedback feedback, QWidget* field = nullptr); // 显示原因，按需定位字段。

        ks::ui::ParameterWorkspace* m_workspace = nullptr; // 共享滚动参数区及固定动作框架。
        ks::ui::AsyncOperation* m_saveOperation = nullptr; // 项目保存的唯一在途事务。
        BreakpointDraftModel* m_drafts = nullptr; // 当前页草稿模型，拥有已提交的定义。
        QTableView* m_table = nullptr; // 单选草稿表，与表单的编辑对象独立。
        QPersistentModelIndex m_editing; // 行号变化时仍指向开始编辑的定义。
        ProjectContext m_project; // 正在编辑的实际项目及存储基准。
        std::optional<ProjectContext> m_pendingProject; // 待载入的已核验项目或新修订。
        Ksword::ActionAnalyze::ProjectError m_saveError = Ksword::ActionAnalyze::ProjectError::None; // 最近存储错误。
        bool m_saving = false; // 冻结表单和草稿直到写入回执到达。
        bool m_saved = false; // 最近一次保存结果仍适用于当前草稿。
        bool m_revisionStale = false; // 磁盘基准已过期，等待工作台刷新。

        QGroupBox* m_form = nullptr; // 参数分区标题显示新增或编辑语义。
        QLabel* m_editTarget = nullptr; // 保留编辑对象的原始定位，独立于可修改的字段。
        QLabel* m_editIdentity = nullptr; // 已保存的精确映像/PDB 标识。
        QLabel* m_moduleLabel = nullptr; // 与模块输入关联的明确标签。
        QLabel* m_kindLabel = nullptr; // 与定位选项关联的明确标签。
        QLabel* m_locationLabel = nullptr; // 随定位类型变化的值字段标签。
        QLineEdit* m_module = nullptr; // 用户输入的模块文件名。
        QComboBox* m_kind = nullptr; // 模块内 RVA / 调试符号选择。
        QLineEdit* m_location = nullptr; // 尚未提交的 RVA 或符号文本。
        QCheckBox* m_enabled = nullptr; // 希望在定义上保存的启用意图。

        QPushButton* m_commit = nullptr; // 提交当前表单到内存草稿列表。
        QPushButton* m_clear = nullptr; // 清除输入或离开当前定义编辑。
        QPushButton* m_edit = nullptr; // 明确用所选定义填入表单。
        QPushButton* m_remove = nullptr; // 明确删除列表中的所选定义。
        QPushButton* m_prepareLive = nullptr; // 将所选模块RVA定义带入已有进程执行草稿。
        std::function<bool(const QString&, std::uint32_t, const QString&, const QString&)> m_livePreparation; // 模块/RVA/定义/原项目的纯UI端口。
        QPushButton* m_save = nullptr; // 保存当前项目的整个断点草稿。
        QPushButton* m_openPending = nullptr; // 显式处理待切换项目或已保存的新修订。
        QLabel* m_projectLabel = nullptr; // 保存目标的项目标题、路径和基准修订。
        QLabel* m_projectStatus = nullptr; // 保存、失败或待切换的存储状态。
        QLabel* m_activation = nullptr; // 固定显示本页可核实的原生状态。
        QLabel* m_summary = nullptr; // 草稿数量和空结果说明。
        QLabel* m_feedbackLabel = nullptr; // 最近表单/列表动作的回执。
        Feedback m_feedback = Feedback::None; // 保留语言切换后可重绘的回执身份。
    };
}
