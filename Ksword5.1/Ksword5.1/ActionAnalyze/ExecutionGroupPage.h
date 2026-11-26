#pragma once

#include "ExecutionGroupSession.h"
#include <QWidget>

class QCheckBox;
class QEvent;
class QGroupBox;
class QLabel;
class QLineEdit;
class QPushButton;
class QTimer;
namespace ks::ui { class TableActionTableView; class StructuredFieldView; }

namespace ks::action_analyze
{
    class ExecutionGroupMemberModel;
    class ExecutionGroupSiteEditor;
    class PrivateExecutionRangePane;
    class NativeSessionApiPane;
    class ProcessGroupMemoryPane;

    // 独立执行集合参数/管理页；不借用暂停集合或旧档案的控制权。
    class ExecutionGroupPage final : public QWidget
    {
    public:
        explicit ExecutionGroupPage(QWidget* parent); // 创建共享布局与导航内容，不自动附加。
        ~ExecutionGroupPage() override; // 非阻塞请求原worker清退，退出租约持续保活。

    protected:
        void changeEvent(QEvent* event) override; // 语言更新保留目录、草稿、选择和原票据。

    private:
        void AddSite(bool replace); // 冻结当前单站点表单，显式加入或替换草稿选中项。
        void LoadSite(); // 显式载入唯一选中的完整草稿，不以列表选择覆盖未保存表单。
        void RemoveSites(); // 仅从未启动目录移除点击时选中行。
        void Start(); // 在原worker上创建并启动唯一集合。
        void AddRange(std::uint64_t address, std::uint64_t bytes); // 冻结单选成员的完整停点，将范围交原worker追加。
        void CaptureApi(); // 冻结单选原成员及另一来源，确认后交本端原worker采集。
        void Memory(bool save); // 读取当前唯一成员范围，或保存冻结的原读取字节；不Continue。
        void Submit(ExecutionGroupCommand command, bool all = false,
            execution_group_native::NativeStepMode mode = execution_group_native::NativeStepMode::Into); // 复制原生完整快照入队。
        void Poll(); // 只复制worker已公布值；不在UI执行Query。
        void Render(); // 状态和全部按钮资格来自同一已显示回执。
        void Detail(); // 统一字段文档，选择改变只更新展示。
        std::vector<int> Selected(bool all = false) const; // 返回完整所选行序列，不借首行代表批次。

        ExecutionGroupSiteEditor* m_editor = nullptr; // 独立单站点输入草稿。
        PrivateExecutionRangePane* m_rangePane = nullptr; // 活集合独立范围草稿，复用单目标页面组件。
        NativeSessionApiPane* m_apiPane = nullptr; // 原参数正文中复用来源身份和有限时长，不另建页面。
        ProcessGroupMemoryPane* m_memoryPane = nullptr; // 复用原停点范围输入，隐藏重复项目字段。
        QPushButton* m_captureApi = nullptr; // 固定动作栏的同采样采集入口，所属原成员在点击时冻结。
        QLabel* m_rangeTarget = nullptr; // 明确本次追加动作的真实实例和停点，与Start草稿分开。
        ExecutionGroupMemberModel* m_model = nullptr; // Start冻结的1..16行目录。
        ks::ui::TableActionTableView* m_members = nullptr; // 多选管理表，操作条None。
        ks::ui::StructuredFieldView* m_fields = nullptr; // 所选成员和全部操作回执的唯一字段源。
        QCheckBox* m_authorized = nullptr; // 对完整目录的显式控制授权。
        QGroupBox* m_projectSection = nullptr; // Start之前可编辑，原结果使用worker中的真实项目身份。
        QLineEdit* m_projectDirectory = nullptr; // 可选项目路径草稿；空值不创建项目。
        QCheckBox* m_openProject = nullptr; // 明确打开已有项目并创建新sample，不猜目录用途。
        QLabel* m_status = nullptr; // 草稿错误、回读时间、清退责任分层显示。
        QPushButton* m_add = nullptr; // 加入下一站点。
        QPushButton* m_replace = nullptr; // 用完整输入替换选中草稿行。
        QPushButton* m_load = nullptr; // 将保存的完整成员草稿载回编辑器。
        QPushButton* m_remove = nullptr; // 移除选中草稿成员。
        QPushButton* m_start = nullptr; // 开始原生集合。
        QPushButton* m_newDraft = nullptr; // clean之后显式返回目录草稿。
        QPushButton* m_pauseAll = nullptr; // 固定全集在原执行owner内主动暂停。
        QPushButton* m_pauseSelected = nullptr; // 明确所选子集在原执行owner内主动暂停。
        QPushButton* m_continueAll = nullptr; // 全部固定成员当前票据继续。
        QPushButton* m_continueSelected = nullptr; // 全部所选成员当前票据继续。
        QPushButton* m_into = nullptr; // 唯一选中成员步入。
        QPushButton* m_over = nullptr; // 唯一选中成员步过调用。
        QPushButton* m_out = nullptr; // 唯一选中成员跳出。
        QPushButton* m_cancel = nullptr; // 唯一选中成员原步进请求取消。
        QPushButton* m_save = nullptr; // 显式保存唯一成员当前执行事件，不继续目标。
        QPushButton* m_query = nullptr; // 请求原worker状态回读。
        QPushButton* m_close = nullptr; // 关闭新动作准入并清退原owner。
        QTimer* m_poll = nullptr; // 已公布值展示定时器，不承担原生采样。
        std::unique_ptr<ExecutionGroupSession> m_session; // clean前不替换的本端原生会话。
        ExecutionGroupSessionSnapshot m_shown; // 用户当前实际看到的完整结果，动作据此冻结。
        QString m_inputError; // 输入或入队失败，不覆盖原生结果。
        bool m_registered = false; // 单例常驻所有者登记准入。
    };
}
